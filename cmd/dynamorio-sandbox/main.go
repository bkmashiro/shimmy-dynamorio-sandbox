// cmd/dynamorio-sandbox/main.go – transparent wrapper that runs a program
// under the DynamoRIO syscall-virtualization sandbox via a Docker carrier.
//
// Preferred usage:
//
//	dynamorio-sandbox [flags] -- /path/to/evaluator arg1 arg2
//
// Legacy usage with --exec/--args is still accepted for compatibility.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	defaultImage     = "dynamorio-sandbox"
	drrunPath        = "/opt/dynamorio/bin64/drrun"
	filterSOPath     = "/opt/sandbox/syscall_filter.so"
	sandboxBaseInCtr = "/tmp/dr-sandbox"
)

type sandboxConfig struct {
	Exec         string
	Args         []string
	Timeout      time.Duration
	KillAfter    time.Duration
	Mem          string
	Procs        int
	Image        string
	DryRun       bool
	SessionID    string
	Mode         string
	RedirectTmp  bool
	PolicyFile   string
	Verbose      bool
	Workdir      string
	EvaluatorEnv map[string]string
	Env          map[string]string
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func parseCLI(args []string) (sandboxConfig, error) {
	cfg := sandboxConfig{
		Timeout:      30 * time.Second,
		KillAfter:    5 * time.Second,
		Image:        defaultImage,
		Mode:         "observe",
		RedirectTmp:  true,
		EvaluatorEnv: map[string]string{},
		Env:          map[string]string{},
	}

	fs := flag.NewFlagSet("dynamorio-sandbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	legacyExec := fs.String("exec", "", "Program to execute inside the sandbox")
	legacyArgs := fs.String("args", "", "Space-separated arguments for the program")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "Maximum execution time (e.g. 30s, 2m)")
	fs.DurationVar(&cfg.KillAfter, "timeout-kill-after", cfg.KillAfter, "Grace period after timeout before force-killing evaluator subprocesses")
	fs.StringVar(&cfg.Mem, "max-mem", "", "DR allocation budget via DR_MAX_ALLOC_BYTES (e.g. 128m, 1g); empty = unlimited")
	fs.IntVar(&cfg.Procs, "max-procs", 0, "DR process limit via DR_MAX_PROCS; 0 = client default")
	fs.StringVar(&cfg.Image, "image", cfg.Image, "Docker image to use")
	fs.BoolVar(&cfg.DryRun, "dry-run", false, "Print docker command without executing")
	fs.StringVar(&cfg.SessionID, "session", "", "Session ID (auto-generated if empty)")
	fs.StringVar(&cfg.Mode, "mode", cfg.Mode, "DR sandbox mode: observe or strict")
	fs.BoolVar(&cfg.RedirectTmp, "redirect-tmp", cfg.RedirectTmp, "Redirect private temp/cache writes into the session VFS")
	fs.StringVar(&cfg.PolicyFile, "policy-file", "", "Path to env-style DR policy file")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "Print wrapper status messages to stderr")
	fs.StringVar(&cfg.Workdir, "workdir", "", "Evaluator working directory to bind-mount and use inside the carrier (default: current directory)")
	evaluatorEnvValues := multiFlag{}
	passEnvValues := multiFlag{}
	fs.Var(&evaluatorEnvValues, "env", "Evaluator env KEY=VALUE; may be repeated")
	fs.Var(&passEnvValues, "pass-env", "Pass host env KEY into the evaluator carrier; may be repeated")

	pathPolicy := fs.String("path-policy", "", "DR_PATH_POLICY rules, e.g. ro:/data;private:/tmp/work;block:/secrets")
	networkPolicy := fs.String("network-policy", "", "Network policy: allow/block or fine rules such as allow:127.0.0.1:9;block:*")
	execPolicy := fs.String("exec-policy", "", "execve policy override: allow or block")
	protExecPolicy := fs.String("prot-exec-policy", "", "Executable-memory policy override: allow or block")
	fileWritePolicy := fs.String("file-write-policy", "", "File-write policy override: allow, block/stdio, or block:/path for fd policy")
	maxReadBytes := fs.String("max-read-bytes", "", "Per-read cap passed to DR_MAX_READ_BYTES, e.g. 1m or 4096")
	drMaxProcs := fs.Int("dr-max-procs", 0, "Alias for --max-procs; passed to DR_MAX_PROCS")
	auditPath := fs.String("audit-path", "", "Write DR audit JSONL to this side-channel path")
	semanticAudit := fs.Bool("semantic-audit", false, "Enable semantic audit JSONL events")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.PolicyFile != "" {
		policyEnv, err := loadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return cfg, err
		}
		for k, v := range policyEnv {
			cfg.Env[k] = v
		}
	}
	for _, item := range evaluatorEnvValues {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return cfg, fmt.Errorf("--env expects KEY=VALUE, got %q", item)
		}
		cfg.EvaluatorEnv[key] = value
	}
	for _, key := range passEnvValues {
		if key == "" {
			return cfg, errors.New("--pass-env expects a non-empty KEY")
		}
		cfg.EvaluatorEnv[key] = os.Getenv(key)
	}

	setIf := func(k, v string) {
		if v != "" {
			cfg.Env[k] = v
		}
	}
	setIf("DR_PATH_POLICY", *pathPolicy)
	if *networkPolicy != "" {
		if isSimplePolicySwitch(*networkPolicy) {
			cfg.Env["DR_NETWORK"] = *networkPolicy
		} else {
			cfg.Env["DR_NETWORK_POLICY"] = *networkPolicy
		}
	}
	setIf("DR_EXEC", *execPolicy)
	setIf("DR_PROT_EXEC", *protExecPolicy)
	if *fileWritePolicy != "" {
		if strings.ContainsAny(*fileWritePolicy, ":;") {
			cfg.Env["DR_FD_WRITE_POLICY"] = *fileWritePolicy
		} else {
			cfg.Env["DR_FILE_WRITE"] = *fileWritePolicy
		}
	}
	setIf("DR_MAX_READ_BYTES", *maxReadBytes)
	setIf("DR_MAX_ALLOC_BYTES", cfg.Mem)
	if *auditPath != "" {
		cfg.Env["DR_AUDIT_PATH"] = *auditPath
	}
	if *semanticAudit {
		cfg.Env["DR_SEMANTIC_AUDIT"] = "1"
	}
	procLimit := *drMaxProcs
	if procLimit <= 0 {
		procLimit = cfg.Procs
	}
	if procLimit > 0 {
		cfg.Env["DR_MAX_PROCS"] = fmt.Sprintf("%d", procLimit)
	}

	remaining := fs.Args()
	if len(remaining) > 0 {
		cfg.Exec = remaining[0]
		cfg.Args = append([]string(nil), remaining[1:]...)
	} else if *legacyExec != "" {
		cfg.Exec = *legacyExec
		if *legacyArgs != "" {
			cfg.Args = strings.Fields(*legacyArgs)
		}
	} else {
		return cfg, errors.New("missing evaluator command; use dynamorio-sandbox [flags] -- <program> [args...]")
	}

	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("%d-%s", os.Getpid(), randomHex(4))
	}
	if cfg.KillAfter <= 0 {
		return cfg, errors.New("--timeout-kill-after must be positive")
	}
	if cfg.Workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return cfg, err
		}
		cfg.Workdir = wd
	}
	return cfg, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func isSimplePolicySwitch(value string) bool {
	switch value {
	case "allow", "block", "deny", "strict", "0", "1", "true", "false", "yes", "no", "on", "off":
		return true
	default:
		return false
	}
}

func loadPolicyFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, lineNo)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || !strings.HasPrefix(key, "DR_") {
			return nil, fmt.Errorf("%s:%d: policy keys must be non-empty DR_* names", path, lineNo)
		}
		out[key] = value
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func containerName(sessionID string) string {
	var b strings.Builder
	b.WriteString("dr-sandbox-")
	lastDash := false
	for _, r := range sessionID {
		valid := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.'
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	name := strings.Trim(b.String(), "-.")
	if name == "" || name == "dr-sandbox" {
		return "dr-sandbox-session"
	}
	return name
}

func durationSecondsString(d time.Duration) string {
	seconds := d.Seconds()
	if seconds == float64(int64(seconds)) {
		return fmt.Sprintf("%.0fs", seconds)
	}
	value := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", seconds), "0"), ".")
	return value + "s"
}

func buildDockerArgs(cfg sandboxConfig) []string {
	dockerArgs := []string{
		"run", "--rm", "-i", "--init",
		"--name", containerName(cfg.SessionID),
		"--security-opt", "seccomp=unconfined",
		"--cap-drop", "ALL",
		"-v", fmt.Sprintf("%s:%s", cfg.Workdir, cfg.Workdir),
		"-w", cfg.Workdir,
		"-e", fmt.Sprintf("DR_SESSION_ID=%s", cfg.SessionID),
		"-e", fmt.Sprintf("DR_SANDBOX_MODE=%s", cfg.Mode),
		"-e", fmt.Sprintf("DR_REDIRECT_TMP=%t", cfg.RedirectTmp),
	}

	keys := make([]string, 0, len(cfg.Env))
	for k := range cfg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if cfg.Env[k] != "" {
			dockerArgs = append(dockerArgs, "-e", fmt.Sprintf("%s=%s", k, cfg.Env[k]))
		}
	}
	evalKeys := make([]string, 0, len(cfg.EvaluatorEnv))
	for k := range cfg.EvaluatorEnv {
		evalKeys = append(evalKeys, k)
	}
	sort.Strings(evalKeys)
	for _, k := range evalKeys {
		dockerArgs = append(dockerArgs, "-e", fmt.Sprintf("%s=%s", k, cfg.EvaluatorEnv[k]))
	}

	innerCmd := []string{
		"timeout", fmt.Sprintf("--kill-after=%s", durationSecondsString(cfg.KillAfter)), durationSecondsString(cfg.Timeout),
		drrunPath,
		"-c", filterSOPath,
		"--",
		cfg.Exec,
	}
	innerCmd = append(innerCmd, cfg.Args...)
	dockerArgs = append(dockerArgs, cfg.Image)
	dockerArgs = append(dockerArgs, innerCmd...)
	return dockerArgs
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: dynamorio-sandbox [flags] -- <program> [args...]\n")
	fmt.Fprintf(os.Stderr, "       dynamorio-sandbox --exec <program> --args '<args>' [flags]  # legacy\n")
}

func main() {
	cfg, err := parseCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		usage()
		os.Exit(2)
	}

	dockerArgs := buildDockerArgs(cfg)
	if cfg.DryRun {
		fmt.Printf("docker %s\n", strings.Join(dockerArgs, " "))
		return
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] session=%s exec=%s timeout=%s\n",
			cfg.SessionID, cfg.Exec, cfg.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout+cfg.KillAfter+5*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "\n[dynamorio-sandbox] caught %s; killing carrier\n", sig)
			}
			cancel()
		case <-ctx.Done():
		}
	}()

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	start := time.Now()
	err = cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			if cfg.Verbose {
				fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] TIMEOUT after %s\n", elapsed.Round(time.Millisecond))
			}
			os.Exit(124)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] carrier error: %v\n", err)
		os.Exit(1)
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] completed in %s\n", elapsed.Round(time.Millisecond))
	}
}
