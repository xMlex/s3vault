package cli

import (
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
)

func newProfileCmd(state *runState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage shared encryption profiles",
	}

	cmd.AddCommand(newProfileAddCmd(state))
	cmd.AddCommand(newProfileListCmd(state))
	cmd.AddCommand(newProfileUpdateCmd(state))
	cmd.AddCommand(newProfileRemoveCmd(state))

	return cmd
}

func newProfileAddCmd(state *runState) *cobra.Command {
	var name, file, nativeKeyEnv string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Create a shared encryption profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			config, err := readEncryption(cmd.InOrStdin(), file)
			if err != nil {
				return err
			}

			if config == nil {
				return errors.New("--file is required and must contain a non-empty mode")
			}

			kek, err := readProfileKEK(nativeKeyEnv, config)
			if err != nil {
				return err
			}

			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			p, err := id.AddEncryptionProfile(cmd.Context(), name, config, kek)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nuid=%s\nmode=%s\n",
				p.Name, p.UID, profileMode(p.Config))

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	cmd.Flags().StringVar(&file, "file", "", "JSON encryption profile file, or - for stdin (required)")
	cmd.Flags().StringVar(&nativeKeyEnv, "native-key-env", "",
		"seal a native KEK read from this environment variable into the database")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

//nolint:dupl // the command shape mirrors target list; the loaders and writers differ.
func newProfileListCmd(state *runState) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List shared encryption profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			profiles, err := id.ListEncryptionProfiles(cmd.Context())
			if err != nil {
				return err
			}

			switch output {
			case outputText:
				return writeProfilesText(cmd.OutOrStdout(), profiles)
			case outputJSON:
				return writeProfilesJSON(cmd.OutOrStdout(), profiles)
			default:
				return fmt.Errorf("unknown output format %q: use text or json", output)
			}
		},
	}

	cmd.Flags().StringVar(&output, "output", outputText, "output format: text|json")

	return cmd
}

func newProfileUpdateCmd(state *runState) *cobra.Command {
	var name, file, newName, nativeKeyEnv string

	var force bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Replace a shared encryption profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !force {
				return errors.New("--force is required: changing a shared profile affects every user assigned to it")
			}

			config, err := readEncryption(cmd.InOrStdin(), file)
			if err != nil {
				return err
			}

			if config == nil {
				return errors.New("--file is required and must contain a non-empty mode")
			}

			kek, err := readProfileKEK(nativeKeyEnv, config)
			if err != nil {
				return err
			}

			id, err := openUserAuth(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			p, err := id.UpdateEncryptionProfile(cmd.Context(), name, config, newName, kek)
			if err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nuid=%s\nmode=%s\nusers=%d\n",
				p.Name, p.UID, profileMode(p.Config), p.Users)

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	cmd.Flags().StringVar(&file, "file", "", "JSON encryption profile file, or - for stdin (required)")
	cmd.Flags().StringVar(&newName, "new-name", "", "rename the profile")
	cmd.Flags().StringVar(&nativeKeyEnv, "native-key-env", "",
		"seal a native KEK read from this environment variable; omit to clear a previously sealed key")
	cmd.Flags().BoolVar(&force, "force", false, "confirm a change that affects every assigned user")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("file")

	return cmd
}

//nolint:dupl // the command shape mirrors target remove; the operator messages differ.
func newProfileRemoveCmd(state *runState) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove an unassigned shared encryption profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := openUserAuthInspect(cmd.Context(), state.cfg)
			if err != nil {
				return err
			}
			defer id.Close()

			if err := id.RemoveEncryptionProfile(cmd.Context(), name); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "name=%s\nremoved=true\n", name)

			return err
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}

type profileJSON struct {
	UID        string          `json:"uid"`
	Name       string          `json:"name"`
	Encryption json.RawMessage `json:"encryption"`
	Users      int64           `json:"users,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

func writeProfilesText(w io.Writer, profiles []postgresauth.EncryptionProfile) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAME\tMODE\tUSERS\tCREATED"); err != nil {
		return err
	}

	for _, p := range profiles {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			p.Name, profileMode(p.Config), p.Users, p.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}

	return tw.Flush()
}

func writeProfilesJSON(w io.Writer, profiles []postgresauth.EncryptionProfile) error {
	out := make([]profileJSON, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileJSON{
			UID:        p.UID,
			Name:       p.Name,
			Encryption: p.Config,
			Users:      p.Users,
			CreatedAt:  p.CreatedAt,
			UpdatedAt:  p.UpdatedAt,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

// readProfileKEK seals a KEK for a native/keyfile profile. The value comes from
// the environment, never from argv, so it does not leak into shell history or
// the process list.
func readProfileKEK(envName string, config json.RawMessage) ([]byte, error) {
	if envName == "" {
		return nil, nil
	}

	var p struct {
		Mode   string `json:"mode"`
		Native struct {
			Wrap    string `json:"wrap"`
			KeyFile string `json:"key_file"`
			KeyEnv  string `json:"key_env"`
		} `json:"native"`
	}

	if err := json.Unmarshal(config, &p); err != nil {
		return nil, fmt.Errorf("parse encryption profile: %w", err)
	}

	if !strings.EqualFold(strings.TrimSpace(p.Mode), "native") {
		return nil, errors.New("--native-key-env requires mode=native")
	}

	wrap := strings.ToLower(strings.TrimSpace(p.Native.Wrap))
	if wrap != "" && wrap != "keyfile" {
		return nil, fmt.Errorf("--native-key-env requires native.wrap=keyfile, got %q", wrap)
	}

	if p.Native.KeyFile != "" || p.Native.KeyEnv != "" {
		return nil, errors.New("--native-key-env is exclusive with native.key_file and native.key_env")
	}

	raw, ok := os.LookupEnv(envName)
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("environment variable %s is not set", envName)
	}

	return encrypt.ParseKEKEnv(raw)
}
