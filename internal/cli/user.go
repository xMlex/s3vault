package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xMlex/s3vault/internal/adapter/encrypt"
	postgresauth "github.com/xMlex/s3vault/internal/adapter/s3auth/postgres"
	"github.com/xMlex/s3vault/internal/adapter/s3target"
	"github.com/xMlex/s3vault/internal/config"
	"github.com/xMlex/s3vault/internal/port"
)

const (
	outputText  = "text"
	outputJSON  = "json"
	labelGlobal = "global"
)

func newUserCmd(state *runState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage gateway users in PostgreSQL",
	}

	cmd.AddCommand(newUserAddCmd(state))
	cmd.AddCommand(newUserListCmd(state))
	cmd.AddCommand(newUserUpdateCmd(state))
	cmd.AddCommand(newUserRotateCmd(state))
	cmd.AddCommand(newUserDisableCmd(state, false))
	cmd.AddCommand(newUserDisableCmd(state, true))

	return cmd
}

func newUserAddCmd(state *runState) *cobra.Command {
	var (
		name              string
		prefix            string
		accessKey         string
		encryptionProfile string
		target            string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a gateway user and print its secret once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			u, secret, err := id.AddUser(cmd.Context(), postgresauth.AddParams{
				Name:                  name,
				AccessKeyID:           accessKey,
				Prefix:                prefix,
				EncryptionProfileName: encryptionProfile,
				TargetName:            target,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "access_key_id=%s\nsecret_key=%s\n", u.AccessKeyID, secret); err != nil {
				return err
			}

			_, err = fmt.Fprintf(out, "name=%s\nprefix=%s\nencryption_profile=%s\ns3_target=%s\ns3=%s\n",
				u.Name, u.Prefix, userProfileName(u), userTargetName(u), userTargetLabel(u))

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "display name (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "transparent key prefix (required)")
	cmd.Flags().StringVar(&accessKey, "access-key", "", "access key id (generated when empty)")
	cmd.Flags().StringVar(&encryptionProfile, "encryption-profile", "", "shared encryption profile name (default: gateway profile)")
	cmd.Flags().StringVar(&target, "s3-target", "", "shared destination S3 target name (default: global S3)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("prefix")

	return cmd
}

//nolint:dupl // the command shape mirrors target/profile list; the loaders and writers differ.
func newUserListCmd(state *runState) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List gateway users",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			users, err := id.ListUsers(cmd.Context())
			if err != nil {
				return err
			}

			switch output {
			case outputText:
				return writeUsersText(cmd.OutOrStdout(), users)
			case outputJSON:
				return writeUsersJSON(cmd.OutOrStdout(), users)
			default:
				return fmt.Errorf("unknown output format %q: use text or json", output)
			}
		},
	}

	cmd.Flags().StringVar(&output, "output", outputText, "output format: text|json")

	return cmd
}

//nolint:gocyclo // one command keeps every update flag and its mutual exclusions in one place.
func newUserUpdateCmd(state *runState) *cobra.Command {
	var (
		accessKey         string
		prefix            string
		encryptionProfile string
		clearProfile      bool
		target            string
		clearTarget       bool
		force             bool
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Change a user's prefix, encryption profile or destination",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			changedPrefix := cmd.Flags().Changed("prefix")
			changedProfile := cmd.Flags().Changed("encryption-profile")
			changedTarget := cmd.Flags().Changed("s3-target")

			if !changedPrefix && !changedProfile && !clearProfile && !changedTarget && !clearTarget {
				return errors.New("nothing to update: set --prefix, --encryption-profile, --clear-encryption, --s3-target, or --clear-s3-target")
			}

			if !force {
				return errors.New("--force is required: changing prefix, encryption or destination can make existing objects unreachable")
			}

			if clearProfile && changedProfile {
				return errors.New("--clear-encryption and --encryption-profile are mutually exclusive")
			}

			if clearTarget && changedTarget {
				return errors.New("--clear-s3-target and --s3-target are mutually exclusive")
			}

			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			params := postgresauth.UpdateParams{
				ClearEncryption: clearProfile,
				ClearTarget:     clearTarget,
			}
			if changedPrefix {
				params.Prefix = &prefix
			}

			if changedProfile {
				params.EncryptionProfileName = &encryptionProfile
			}

			if changedTarget {
				params.TargetName = &target
			}

			u, err := id.UpdateUser(cmd.Context(), accessKey, params)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"access_key_id=%s\nname=%s\nprefix=%s\nencryption_profile=%s\ns3_target=%s\ns3=%s\nenabled=%t\n",
				u.AccessKeyID, u.Name, u.Prefix, userProfileName(u), userTargetName(u), userTargetLabel(u), u.Enabled)

			return err
		},
	}

	cmd.Flags().StringVar(&accessKey, "access-key", "", "access key id (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "new transparent key prefix")
	cmd.Flags().StringVar(&encryptionProfile, "encryption-profile", "", "shared encryption profile name")
	cmd.Flags().BoolVar(&clearProfile, "clear-encryption", false, "use the gateway's global encryption profile")
	cmd.Flags().StringVar(&target, "s3-target", "", "shared destination S3 target name")
	cmd.Flags().BoolVar(&clearTarget, "clear-s3-target", false, "use the gateway's global S3 destination")
	cmd.Flags().BoolVar(&force, "force", false, "confirm a prefix/profile/destination change")
	_ = cmd.MarkFlagRequired("access-key")

	return cmd
}

func newUserRotateCmd(state *runState) *cobra.Command {
	var accessKey string

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Replace a user's secret and print the new one once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			secret, err := id.RotateSecret(cmd.Context(), accessKey)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "access_key_id=%s\nsecret_key=%s\n", accessKey, secret)

			return err
		},
	}

	cmd.Flags().StringVar(&accessKey, "access-key", "", "access key id (required)")
	_ = cmd.MarkFlagRequired("access-key")

	return cmd
}

func newUserDisableCmd(state *runState, enable bool) *cobra.Command {
	var accessKey string

	name := "disable"
	short := "Disable a user immediately"

	if enable {
		name = "enable"
		short = "Enable a previously disabled user"
	}

	cmd := &cobra.Command{
		Use:   name,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			if err := id.SetEnabled(cmd.Context(), accessKey, enable); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "access_key_id=%s\nenabled=%t\n", accessKey, enable)

			return err
		},
	}

	cmd.Flags().StringVar(&accessKey, "access-key", "", "access key id (required)")
	_ = cmd.MarkFlagRequired("access-key")

	return cmd
}

func openUserAuth(ctx context.Context, cfg config.Config) (*postgresauth.Identity, error) {
	return openUserAuthWith(ctx, cfg, false)
}

// openUserAuthInspect opens the same identity without the startup validation
// pass. List/remove/disable and reference-only update commands use it: one
// corrupt row must not lock the operator out of seeing or removing that row.
// Commands that create or re-seal a secret still use openUserAuth, so the
// master key is validated first.
func openUserAuthInspect(ctx context.Context, cfg config.Config) (*postgresauth.Identity, error) {
	return openUserAuthWith(ctx, cfg, true)
}

func openUserAuthWith(ctx context.Context, cfg config.Config, skipValidation bool) (*postgresauth.Identity, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if strings.TrimSpace(cfg.Server.Auth.DSN) == "" {
		return nil, errors.New("server.auth.dsn is required for user management")
	}

	masterKey, err := authMasterKey()
	if err != nil {
		return nil, err
	}

	pgCfg := postgresauth.Config{
		DSN:            cfg.Server.Auth.DSN,
		MaxConns:       cfg.Server.Auth.MaxConns,
		QueryTimeout:   cfg.Server.Auth.QueryTimeout,
		MasterKey:      masterKey,
		Bucket:         userAuthBucket(cfg),
		SkipValidation: skipValidation,
	}

	if !skipValidation {
		profiles, err := encrypt.NewResolver(cfg.Encryption)
		if err != nil {
			return nil, err
		}

		pgCfg.ValidateEncryption = func(raw json.RawMessage) error {
			_, err := profiles.ResolveRaw(raw)

			return err
		}
	}

	return postgresauth.Open(ctx, pgCfg)
}

func userAuthBucket(cfg config.Config) string {
	if cfg.Server.S3Bucket != "" {
		return cfg.Server.S3Bucket
	}

	if cfg.S3.Bucket != "" {
		return cfg.S3.Bucket
	}

	return defaultVirtualBucket
}

func readEncryption(stdin io.Reader, path string) (json.RawMessage, error) {
	switch path {
	case "":
		return nil, nil
	case "-":
		body, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read encryption profile: %w", err)
		}

		return normalizeProfileJSON(body)
	default:
		body, err := os.ReadFile(path) //nolint:gosec // operator-supplied profile path
		if err != nil {
			return nil, fmt.Errorf("read encryption profile %s: %w", path, err)
		}

		return normalizeProfileJSON(body)
	}
}

func normalizeProfileJSON(body []byte) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return nil, nil
	}

	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return nil, fmt.Errorf("parse encryption profile: %w", err)
	}

	return json.RawMessage(trimmed), nil
}

func writeUsersText(w io.Writer, users []postgresauth.User) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tNAME\tACCESS_KEY\tPREFIX\tPROFILE\tTARGET\tS3\tMODE\tENABLED\tCREATED"); err != nil {
		return err
	}

	for _, u := range users {
		if _, err := fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\n",
			u.ID, u.Name, u.AccessKeyID, u.Prefix, userProfileName(u), userTargetName(u),
			userTargetLabel(u), userProfileMode(u), u.Enabled,
			u.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	return tw.Flush()
}

type profileRefJSON struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}

type userJSON struct {
	ID                int64           `json:"id"`
	Name              string          `json:"name"`
	AccessKeyID       string          `json:"access_key_id"`
	Prefix            string          `json:"prefix"`
	EncryptionProfile *profileRefJSON `json:"encryption_profile"`
	S3Target          *targetJSON     `json:"s3_target"`
	Enabled           bool            `json:"enabled"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func writeUsersJSON(w io.Writer, users []postgresauth.User) error {
	out := make([]userJSON, 0, len(users))
	for _, u := range users {
		r := userJSON{
			ID:          u.ID,
			Name:        u.Name,
			AccessKeyID: u.AccessKeyID,
			Prefix:      u.Prefix,
			Enabled:     u.Enabled,
			CreatedAt:   u.CreatedAt,
			UpdatedAt:   u.UpdatedAt,
		}

		if u.EncryptionProfile != nil {
			r.EncryptionProfile = &profileRefJSON{
				UID:  u.EncryptionProfile.UID,
				Name: u.EncryptionProfile.Name,
				Mode: profileMode(u.EncryptionProfile.Config),
			}
		}

		r.S3Target = targetInfoJSON(u.Target)

		out = append(out, r)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

func userProfileName(u postgresauth.User) string {
	if u.EncryptionProfile == nil {
		return labelGlobal
	}

	return u.EncryptionProfile.Name
}

func userProfileMode(u postgresauth.User) string {
	if u.EncryptionProfile == nil {
		return labelGlobal
	}

	return profileMode(u.EncryptionProfile.Config)
}

func userTargetName(u postgresauth.User) string {
	if u.Target == nil {
		return labelGlobal
	}

	return u.Target.Name
}

func userTargetLabel(u postgresauth.User) string {
	return s3TargetLabel(u.Target)
}

func profileMode(raw json.RawMessage) string {
	if len(raw) == 0 {
		return labelGlobal
	}

	var p struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "invalid"
	}

	if strings.TrimSpace(p.Mode) == "" {
		return labelGlobal
	}

	return p.Mode
}

// readS3Profile reads a full target document. An empty path means no target;
// "-" reads stdin and "path" reads a file. The file may contain the target's
// secret, so it is never echoed or logged.
func readS3Profile(stdin io.Reader, path string) (*port.S3Target, error) {
	body, err := readProfileBody(stdin, path)
	if err != nil {
		return nil, err
	}

	if body == nil {
		return nil, nil
	}

	t, err := s3target.Decode(body)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func readProfileBody(stdin io.Reader, path string) ([]byte, error) {
	switch path {
	case "":
		return nil, nil
	case "-":
		body, err := io.ReadAll(io.LimitReader(stdin, s3target.MaxProfileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read s3 profile: %w", err)
		}

		return checkedProfileBody(body)
	default:
		f, err := os.Open(path) //nolint:gosec // operator-supplied profile path
		if err != nil {
			return nil, fmt.Errorf("read s3 profile %s: %w", path, err)
		}
		defer func() { _ = f.Close() }()

		body, err := io.ReadAll(io.LimitReader(f, s3target.MaxProfileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read s3 profile %s: %w", path, err)
		}

		return checkedProfileBody(body)
	}
}

func checkedProfileBody(body []byte) ([]byte, error) {
	if len(body) > s3target.MaxProfileBytes {
		return nil, fmt.Errorf("s3 profile is larger than %d bytes", s3target.MaxProfileBytes)
	}

	return body, nil
}
