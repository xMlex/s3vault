package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	postgresauth "github.com/xMlex/s3vault/internal/adapter/s3auth/postgres"
	"github.com/xMlex/s3vault/internal/port"
)

func newTargetCmd(state *runState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage shared destination S3 profiles",
	}

	cmd.AddCommand(newTargetAddCmd(state))
	cmd.AddCommand(newTargetListCmd(state))
	cmd.AddCommand(newTargetUpdateCmd(state))
	cmd.AddCommand(newTargetRemoveCmd(state))

	return cmd
}

func newTargetAddCmd(state *runState) *cobra.Command {
	var name, profileFile string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a shared destination S3 profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := readS3Profile(cmd.InOrStdin(), profileFile)
			if err != nil {
				return err
			}

			if target == nil {
				return errors.New("--profile is required")
			}

			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			info, err := id.AddTarget(cmd.Context(), name, *target)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nuid=%s\ns3=%s\n",
				info.Name, info.UID, s3TargetLabel(&info))

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "target name (required)")
	cmd.Flags().StringVar(&profileFile, "profile", "", "JSON target profile file, or - for stdin (required)")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("profile")

	return cmd
}

//nolint:dupl // the command shape mirrors user list; the loaders and writers differ.
func newTargetListCmd(state *runState) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List shared destination S3 profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			targets, err := id.ListTargets(cmd.Context())
			if err != nil {
				return err
			}

			switch output {
			case outputText:
				return writeTargetsText(cmd.OutOrStdout(), targets)
			case outputJSON:
				return writeTargetsJSON(cmd.OutOrStdout(), targets)
			default:
				return fmt.Errorf("unknown output format %q: use text or json", output)
			}
		},
	}

	cmd.Flags().StringVar(&output, "output", outputText, "output format: text|json")

	return cmd
}

func newTargetUpdateCmd(state *runState) *cobra.Command {
	var name, profileFile, newName string

	var force bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Replace a shared destination S3 profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !force {
				return errors.New("--force is required: changing a shared target affects every user assigned to it")
			}

			target, err := readS3Profile(cmd.InOrStdin(), profileFile)
			if err != nil {
				return err
			}

			if target == nil {
				return errors.New("--profile is required")
			}

			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			info, err := id.UpdateTarget(cmd.Context(), name, *target, newName)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nuid=%s\ns3=%s\nusers=%d\n",
				info.Name, info.UID, s3TargetLabel(&info), info.Users)

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "target name (required)")
	cmd.Flags().StringVar(&profileFile, "profile", "", "JSON target profile file, or - for stdin (required)")
	cmd.Flags().StringVar(&newName, "new-name", "", "rename the target")
	cmd.Flags().BoolVar(&force, "force", false, "confirm a change that affects every assigned user")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("profile")

	return cmd
}

//nolint:dupl // the command shape mirrors profile remove; the operator messages differ.
func newTargetRemoveCmd(state *runState) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an unassigned shared destination S3 profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			if err := id.RemoveTarget(cmd.Context(), name); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nremoved=true\n", name)

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "target name (required)")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}

type targetSSEKMSJSON struct {
	KeyID     string            `json:"key_id,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	BucketKey bool              `json:"bucket_key,omitempty"`
}

type targetJSON struct {
	UID          string            `json:"uid"`
	Name         string            `json:"name"`
	Endpoint     string            `json:"endpoint,omitempty"`
	Region       string            `json:"region"`
	Bucket       string            `json:"bucket"`
	Prefix       string            `json:"prefix,omitempty"`
	PathStyle    bool              `json:"path_style"`
	SSEKMS       *targetSSEKMSJSON `json:"sse_kms,omitempty"`
	StorageClass string            `json:"storage_class,omitempty"`
	Users        int64             `json:"users,omitempty"`
	CreatedAt    *time.Time        `json:"created_at,omitempty"`
	UpdatedAt    *time.Time        `json:"updated_at,omitempty"`
}

func targetInfoJSON(t *postgresauth.TargetInfo) *targetJSON {
	if t == nil {
		return nil
	}

	out := &targetJSON{
		UID:          t.UID,
		Name:         t.Name,
		Endpoint:     t.Endpoint,
		Region:       t.Region,
		Bucket:       t.Bucket,
		Prefix:       t.Prefix,
		PathStyle:    t.PathStyle,
		StorageClass: t.StorageClass,
		Users:        t.Users,
	}
	if !t.CreatedAt.IsZero() {
		created := t.CreatedAt
		out.CreatedAt = &created
	}

	if !t.UpdatedAt.IsZero() {
		updated := t.UpdatedAt
		out.UpdatedAt = &updated
	}

	if t.SSEKMS != nil {
		out.SSEKMS = &targetSSEKMSJSON{
			KeyID:     t.SSEKMS.KeyID,
			Context:   t.SSEKMS.Context,
			BucketKey: t.SSEKMS.BucketKey,
		}
	}

	return out
}

func writeTargetsText(w io.Writer, targets []postgresauth.TargetInfo) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tS3\tPREFIX\tSSE\tCLASS\tUSERS\tCREATED"); err != nil {
		return err
	}

	for _, t := range targets {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			t.Name, s3TargetLabel(&t), displayOrDash(t.Prefix), sseLabel(t.SSEKMS),
			displayOrDash(t.StorageClass), t.Users, t.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	return tw.Flush()
}

func writeTargetsJSON(w io.Writer, targets []postgresauth.TargetInfo) error {
	out := make([]*targetJSON, 0, len(targets))
	for i := range targets {
		out = append(out, targetInfoJSON(&targets[i]))
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

func s3TargetLabel(t *postgresauth.TargetInfo) string {
	if t == nil {
		return labelGlobal
	}

	if t.Endpoint == "" {
		return "aws/" + t.Bucket
	}

	return t.Endpoint + "/" + t.Bucket
}

func sseLabel(sse *port.SSEKMS) string {
	if sse == nil {
		return "-"
	}

	return "kms"
}

func displayOrDash(v string) string {
	if v == "" {
		return "-"
	}

	return v
}
