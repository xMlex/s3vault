package s3store

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/domain"
)

// fakeS3 answers just enough of the S3 API for manager.Uploader and records what
// it was asked to do: the number of parts and their sizes. It exists because the
// part size is a client-side choice, so the only honest way to test the knob is to
// put bytes through the real uploader and watch how it cut them.
type fakeS3 struct {
	mu            sync.Mutex
	puts          []int64 // single PutObject body lengths
	parts         []int64 // UploadPart body lengths, in the order the parts were sent
	complete      int     // CompleteMultipartUpload calls
	putHeaders    []http.Header
	createHeaders []http.Header
}

// record applies fn under the lock and returns the part count afterwards, so a
// handler can label its response without reading shared state outside the lock.
// The SDK sends five UploadPart requests at once, so an unguarded len() here is a
// real data race rather than a theoretical one.
func (f *fakeS3) record(fn func()) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	fn()

	return len(f.parts)
}

func (f *fakeS3) snapshot() (puts, parts []int64, complete int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]int64(nil), f.puts...), append([]int64(nil), f.parts...), f.complete
}

func (f *fakeS3) writeHeaders() (put, create []http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()

	put = make([]http.Header, len(f.putHeaders))
	for i, h := range f.putHeaders {
		put[i] = h.Clone()
	}

	create = make([]http.Header, len(f.createHeaders))
	for i, h := range f.createHeaders {
		create[i] = h.Clone()
	}

	return put, create
}

const (
	fakeBucket = "vault"
	fakeUpload = "upload-id"

	// Fixed response bodies. The fake never echoes the request path back: nothing
	// in these tests reads it, and a constant keeps the responses from depending
	// on the URL the SDK happened to build.
	initiateXML = `<InitiateMultipartUploadResult><Bucket>` + fakeBucket +
		`</Bucket><Key>a/b.bin</Key><UploadId>` + fakeUpload + `</UploadId></InitiateMultipartUploadResult>`
	completeXML = `<CompleteMultipartUploadResult><ETag>"final"</ETag>` +
		`<Location>http://127.0.0.1/a/b.bin</Location></CompleteMultipartUploadResult>`
)

// drain consumes the request body and returns its length, which is the only thing
// this fake cares about. It answers 500 instead of failing the test: the handler
// runs on its own goroutine, where t.FailNow is not allowed, and a half-read body
// would show up as a confusing SDK error rather than as the real cause.
func drain(t *testing.T, w http.ResponseWriter, r *http.Request) int64 {
	t.Helper()

	n, err := io.Copy(io.Discard, r.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
		http.Error(w, "read failed", http.StatusInternalServerError)

		return 0
	}

	return n
}

func (f *fakeS3) start(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && query.Has("uploads"):
			w.Header().Set("Content-Type", "application/xml")
			drain(t, w, r)
			f.record(func() { f.createHeaders = append(f.createHeaders, r.Header.Clone()) })
			_, _ = io.WriteString(w, initiateXML)

		case r.Method == http.MethodPut && query.Get("uploadId") != "":
			n := drain(t, w, r)
			count := f.record(func() { f.parts = append(f.parts, n) })
			w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("etag-%d", count)))

		case r.Method == http.MethodPost && query.Get("uploadId") != "":
			drain(t, w, r)
			f.record(func() { f.complete++ })
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, completeXML)

		case r.Method == http.MethodPut:
			n := drain(t, w, r)

			f.record(func() {
				f.puts = append(f.puts, n)
				f.putHeaders = append(f.putHeaders, r.Header.Clone())
			})
			w.Header().Set("ETag", `"single"`)

		default:
			http.Error(w, `{"Code":"MethodNotAllowed"}`, http.StatusNotImplemented)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func newFakeStore(t *testing.T, srv *httptest.Server, partSize int64) *Store {
	t.Helper()

	return newFakeStoreWithOptions(t, srv, partSize, Options{})
}

func newFakeStoreWithOptions(t *testing.T, srv *httptest.Server, partSize int64, opts Options) *Store {
	t.Helper()

	store, err := NewWithOptions(context.Background(), config.S3Config{ //nolint:gosec // fake creds for a local httptest server
		Endpoint:          srv.URL,
		Region:            "us-east-1",
		Bucket:            fakeBucket,
		AccessKey:         "AKIAFAKEFAKEFAKEFAKE",
		SecretKey:         "fakefakefakefakefakefakefakefakefakefake",
		PathStyle:         true,
		MultipartPartSize: partSize,
	}, opts)
	require.NoError(t, err)

	return store
}

// s3.multipart_part_size is the only thing that decides how the client cuts a
// body: the same 11 MiB is three parts at 5 MiB and one single PutObject at
// 25 MiB. Nothing is negotiated and nothing is probed — the store takes what it
// is given, so the size has to be pinned here rather than inferred from a
// successful upload, which looks the same either way.
func TestPutPartSizeDecidesTheSplit(t *testing.T) {
	t.Parallel()

	const payload = 11<<20 + 3

	body := bytes.Repeat([]byte("s3vault"), payload/7+1)[:payload]

	cases := []struct {
		name      string
		partSize  int64
		wantParts []int64
	}{
		{
			name:      "the 5 MiB default, i.e. the S3 minimum, cuts it into three",
			partSize:  config.DefaultMultipartPartSize,
			wantParts: []int64{5 << 20, 5 << 20, 11<<20 + 3 - 2*(5<<20)},
		},
		{
			name:      "explicitly the S3 minimum: the same three parts",
			partSize:  config.MinMultipartPartSize,
			wantParts: []int64{5 << 20, 5 << 20, 11<<20 + 3 - 2*(5<<20)},
		},
		{
			name:     "25 MiB parts: raises the threshold to a single PutObject",
			partSize: 25 << 20,
		},
		{
			name:     "50 MiB parts: also a single PutObject",
			partSize: 50 << 20,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeS3{}
			srv := fake.start(t)
			store := newFakeStore(t, srv, tc.partSize)

			require.NoError(t, store.Put(context.Background(), "a/b.bin", bytes.NewReader(body), domain.PutMeta{}))

			puts, parts, complete := fake.snapshot()
			if len(tc.wantParts) == 0 {
				// A body of at most one part never opens a session: one PutObject,
				// no Create, no Complete.
				assert.Equal(t, []int64{payload}, puts)
				assert.Empty(t, parts)
				assert.Zero(t, complete)

				return
			}

			assert.Empty(t, puts, "a multi-part body must not also be sent whole")
			assert.Equal(t, 1, complete)
			assert.Equal(t, slices.Sorted(slices.Values(tc.wantParts)), slices.Sorted(slices.Values(parts)),
				"parts are sent concurrently, so compare the multiset, not the order")
		})
	}
}

// A body of at most one part never opens a session, whatever the part size, so
// the store must still write it as a plain PutObject rather than falling back to
// an open upload.
func TestPutSmallBodyIsOneRequest(t *testing.T) {
	t.Parallel()

	fake := &fakeS3{}
	srv := fake.start(t)
	store := newFakeStore(t, srv, config.DefaultMultipartPartSize)

	payload := []byte("x-amz-checksum-sha256 is not in the request")
	require.NoError(t, store.Put(context.Background(), "small.txt", bytes.NewReader(payload), domain.PutMeta{
		PlaintextSHA256: strings.Repeat("ab", 32),
		PlaintextSize:   int64(len(payload)),
	}))

	puts, parts, complete := fake.snapshot()
	assert.Equal(t, []int64{int64(len(payload))}, puts)
	assert.Empty(t, parts)
	assert.Zero(t, complete)
}

// The bounds are enforced where the value is consumed. Zero is the one value
// that means "not specified" — it takes the documented default, which is what a
// fragment built by hand (s3test.ConfigFromEnv does exactly that for the
// integration suite) needs. Anything else must be legal.
func TestNewRejectsBadPartSize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		partSize int64
		wantErr  string
	}{
		{name: "one byte", partSize: 1, wantErr: "s3.multipart_part_size"},
		{name: "negative", partSize: -1, wantErr: "s3.multipart_part_size"},
		{name: "just under the S3 minimum", partSize: config.MinMultipartPartSize - 1, wantErr: "at least 5242880"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(context.Background(), config.S3Config{
				Bucket:            fakeBucket,
				MultipartPartSize: tc.partSize,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A fragment that never set the key must behave like one that came through
// config.Load, or every hand-built config in the tree becomes a tripwire. The
// property is "same split as the default", not any particular number of parts —
// what matters is that zero and DefaultMultipartPartSize are indistinguishable.
func TestNewDefaultsZeroPartSize(t *testing.T) {
	t.Parallel()

	const payload = 11<<20 + 3

	put := func(t *testing.T, partSize int64) (puts, parts []int64, complete int) {
		t.Helper()

		fake := &fakeS3{}
		srv := fake.start(t)
		store := newFakeStore(t, srv, partSize)
		require.NoError(t, store.Put(context.Background(), "a/b.bin",
			bytes.NewReader(bytes.Repeat([]byte("z"), payload)), domain.PutMeta{}))

		puts, parts, complete = fake.snapshot()

		return puts, parts, complete
	}

	_, zeroParts, zeroComplete := put(t, 0)
	_, wantParts, wantComplete := put(t, config.DefaultMultipartPartSize)
	// Parts are uploaded concurrently; the recorded order is not the wire order.
	slices.Sort(zeroParts)
	slices.Sort(wantParts)

	assert.Equal(t, wantParts, zeroParts)
	assert.Equal(t, wantComplete, zeroComplete)
	assert.NotEmpty(t, zeroParts, "11 MiB against the 5 MiB default is three parts, not one request")
}

// A destination's SSE-KMS and storage-class settings are sent only when the
// target sets them. "Not set" must leave the headers off entirely so the
// destination keeps its own defaults; sending an empty or STANDARD value would
// be a different request.
func newStoreForServer(t *testing.T, endpoint string) *Store {
	t.Helper()

	store, err := New(context.Background(), config.S3Config{
		Endpoint:  endpoint,
		Region:    "us-east-1",
		Bucket:    fakeBucket,
		AccessKey: "AKIAFAKE",
		SecretKey: "fakefakefakefakefakefakefakefakefakefake",
		PathStyle: true,
	})
	require.NoError(t, err)

	return store
}

// A 206 response carries the returned range in Content-Length and the complete
// object size in Content-Range. ObjectMeta.Size is the object size, matching the
// local store, because callers use it to size a ranged reader.
func TestGetRangeReportsFullObjectSize(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)

			return
		}

		w.Header().Set("Content-Range", "bytes 0-9/100")
		w.Header().Set("Content-Length", "10")
		w.Header().Set("ETag", `"etag"`)
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(make([]byte, 10))
	}))
	t.Cleanup(srv.Close)

	store := newStoreForServer(t, srv.URL)

	body, meta, err := store.GetRange(context.Background(), "k", 0, 9)
	require.NoError(t, err)
	t.Cleanup(func() { _ = body.Close() })

	got, err := io.ReadAll(body)
	require.NoError(t, err)
	assert.Len(t, got, 10)
	assert.Equal(t, int64(100), meta.Size)
}

// S3 answers any range on an empty object with 416. That is not a missing
// object: the local store returns an empty body for the same request, and the
// facade's HEAD/GET paths must see an empty object, not a 500.
func TestGetRangeEmptyObject(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "0")
			w.Header().Set("ETag", `"empty"`)
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		_, _ = io.WriteString(w,
			`<Error><Code>InvalidRange</Code><Message>range</Message><RequestId>r</RequestId><HostId>h</HostId></Error>`)
	}))
	t.Cleanup(srv.Close)

	store := newStoreForServer(t, srv.URL)

	body, meta, err := store.GetRange(context.Background(), "empty", 0, 127)
	require.NoError(t, err)
	t.Cleanup(func() { _ = body.Close() })

	got, err := io.ReadAll(body)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.True(t, meta.Exists)
	assert.Zero(t, meta.Size)
}

func TestPutWriteOptions(t *testing.T) {
	t.Parallel()

	opts := Options{
		ServerSideEncryption: "aws:kms",
		SSEKMSKeyID:          "alias/vault",
		SSEKMSContext:        map[string]string{"tenant": "alice"},
		BucketKeyEnabled:     true,
		StorageClass:         "STANDARD_IA",
	}

	headersOf := func(t *testing.T, opts Options) (put, create http.Header) {
		t.Helper()

		fake := &fakeS3{}
		srv := fake.start(t)
		store := newFakeStoreWithOptions(t, srv, config.DefaultMultipartPartSize, opts)

		// Small body: one PutObject.
		require.NoError(t, store.Put(context.Background(), "small.txt",
			bytes.NewReader([]byte("small")), domain.PutMeta{}))

		// 6 MiB against the 5 MiB part size: CreateMultipartUpload carries the
		// same write options as a single PUT.
		body := bytes.Repeat([]byte("z"), 6<<20)
		require.NoError(t, store.Put(context.Background(), "large.bin",
			bytes.NewReader(body), domain.PutMeta{}))

		puts, creates := fake.writeHeaders()
		require.Len(t, puts, 1)
		require.Len(t, creates, 1)

		return puts[0], creates[0]
	}

	t.Run("absent sends no headers", func(t *testing.T) {
		t.Parallel()

		put, create := headersOf(t, Options{})
		for _, h := range []http.Header{put, create} {
			assert.Empty(t, h.Get("X-Amz-Server-Side-Encryption"))
			assert.Empty(t, h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
			assert.Empty(t, h.Get("X-Amz-Server-Side-Encryption-Context"))
			assert.Empty(t, h.Get("X-Amz-Server-Side-Encryption-Bucket-Key-Enabled"))
			assert.Empty(t, h.Get("X-Amz-Storage-Class"))
		}
	})

	t.Run("sse-kms and storage class on PUT and multipart create", func(t *testing.T) {
		t.Parallel()

		put, create := headersOf(t, opts)

		for _, h := range []http.Header{put, create} {
			assert.Equal(t, "aws:kms", h.Get("X-Amz-Server-Side-Encryption"))
			assert.Equal(t, "alias/vault", h.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
			assert.Equal(t, base64.StdEncoding.EncodeToString([]byte(`{"tenant":"alice"}`)),
				h.Get("X-Amz-Server-Side-Encryption-Context"))
			assert.Equal(t, "true", h.Get("X-Amz-Server-Side-Encryption-Bucket-Key-Enabled"))
			assert.Equal(t, "STANDARD_IA", h.Get("X-Amz-Storage-Class"))
		}
	})
}
