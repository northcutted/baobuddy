package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/northcutted/baobuddy/receiver/internal/config"
	"github.com/northcutted/baobuddy/receiver/internal/openbao"
	"github.com/northcutted/baobuddy/receiver/internal/otel"
	"github.com/northcutted/baobuddy/receiver/internal/receiver"
)

var version = "0.1.0"

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to baobuddy-receiver JSON config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("baobuddy-receiver %s\n", version)
		return
	}

	// When invoked as an SSH forced command, OpenSSH puts the requested command in
	// SSH_ORIGINAL_COMMAND. Only its first word is used: the client can pick a subcommand but
	// never flags or paths.
	cmd := ""
	if flag.NArg() > 0 {
		cmd = strings.TrimSpace(flag.Arg(0))
	} else if orig := strings.TrimSpace(os.Getenv("SSH_ORIGINAL_COMMAND")); orig != "" {
		fields := strings.Fields(orig)
		if len(fields) > 0 {
			cmd = fields[0]
		}
	}

	if cmd == "" {
		usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baobuddy-receiver: %v\n", err)
		os.Exit(1)
	}

	client, err := openbao.NewClient(cfg.OpenBaoAddr, cfg.Namespace, cfg.CACertPath, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baobuddy-receiver: %v\n", err)
		os.Exit(1)
	}

	exporter := otel.NewExporter(
		cfg.OTLPEndpoint,
		cfg.OTLPHeaders,
		cfg.ServiceName,
		cfg.AuditLogPath,
		cfg.MetricsFilePath,
	)

	rcv := receiver.New(cfg, client, exporter)
	var warnings []string
	rcv.Warn = func(msg string) {
		for _, line := range strings.Split(msg, "\n") {
			if !slices.Contains(warnings, line) {
				warnings = append(warnings, line)
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out string
	switch cmd {
	case "install":
		out, err = installFromStdin(ctx, rcv, os.Stdin)
	case "status":
		out, err = rcv.Status(ctx)
	case "revoke":
		out, err = rcv.Revoke(ctx)
	case "pubkey":
		out, err = rcv.PubKey()
	case "tasks":
		out = rcv.Tasks(ctx)
	case "cleanup":
		err = rcv.Cleanup(ctx)
	case "doctor":
		out, err = rcv.Doctor(ctx)
	default:
		fmt.Fprintf(os.Stderr, "baobuddy-receiver: unknown command %q\n", cmd)
		os.Exit(2)
	}

	output := os.Stdout
	if err != nil {
		output = os.Stderr
		fmt.Fprintln(output, err)
	} else if out != "" {
		fmt.Fprintln(output, out)
	}
	for _, warning := range warnings {
		fmt.Fprintln(output, "Warning:", warning)
	}
	if err != nil {
		os.Exit(1)
	}
}

// The config path comes only from argv, never the environment: with sshd's PermitUserEnvironment
// or AcceptEnv, an SSH client could otherwise choose it.
func defaultConfigPath() string {
	return "/etc/baobuddy/receiver.json"
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: baobuddy-receiver [--config path] <install|status|revoke|pubkey|tasks|cleanup|doctor>")
}

// SSH can supply a blocking inherited descriptor that has no deadline support.
// Only the byte copy may block in the background. On timeout the foreground
// install returns before validation or publication, and this one-shot CLI exits.
func installFromStdin(ctx context.Context, r *receiver.Receiver, stdin io.Reader) (string, error) {
	input, writer := io.Pipe()
	defer input.Close()
	stop := context.AfterFunc(ctx, func() { writer.CloseWithError(ctx.Err()) })
	defer stop()
	go func() {
		_, err := io.Copy(writer, stdin)
		writer.CloseWithError(err)
	}()
	return r.Install(ctx, input)
}
