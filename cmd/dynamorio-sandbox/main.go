// cmd/dynamorio-sandbox/main.go – wrapper that runs a program inside the
// DynamoRIO syscall-virtualization sandbox via Docker.
//
// Usage:
//
//	dynamorio-sandbox --exec /bin/ls --args "/tmp" --timeout 30 \
//	    --max-mem 256m --max-procs 5
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultImage     = "dynamorio-sandbox"
	drrunPath        = "/opt/dynamorio/bin64/drrun"
	filterSOPath     = "/opt/sandbox/syscall_filter.so"
	sandboxBaseInCtr = "/tmp/dr-sandbox"
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	execFlag    := flag.String("exec",      "",      "Program to execute inside the sandbox (required)")
	argsFlag    := flag.String("args",      "",      "Space-separated arguments for the program")
	timeoutFlag := flag.Duration("timeout", 30*time.Second, "Maximum execution time (e.g. 30s, 2m)")
	memFlag     := flag.String("max-mem",  "256m",  "Container memory limit (e.g. 128m, 1g)")
	procsFlag   := flag.Int("max-procs",   5,       "Maximum number of processes (--pids-limit)")
	imageFlag   := flag.String("image",    defaultImage, "Docker image to use")
	dryRunFlag  := flag.Bool("dry-run",   false,   "Print docker command without executing")
	sessionFlag := flag.String("session",  "",      "Session ID (auto-generated if empty)")
	flag.Parse()

	if *execFlag == "" {
		fmt.Fprintln(os.Stderr, "error: --exec is required")
		flag.Usage()
		os.Exit(1)
	}

	// Generate session ID
	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = fmt.Sprintf("%d-%s", os.Getpid(), randomHex(4))
	}

	// Split args
	var progArgs []string
	if *argsFlag != "" {
		progArgs = strings.Fields(*argsFlag)
	}

	// Build docker run command
	dockerArgs := []string{
		"run", "--rm",
		"--network=none",
		fmt.Sprintf("--memory=%s", *memFlag),
		fmt.Sprintf("--pids-limit=%d", *procsFlag),
		"--security-opt", "seccomp=unconfined",
		"--cap-drop", "ALL",
		"-e", fmt.Sprintf("DR_SESSION_ID=%s", sessionID),
	}

	// Inner command: timeout + drrun + filter + -- program args
	innerCmd := []string{
		"timeout", fmt.Sprintf("%.0f", timeoutFlag.Seconds()),
		drrunPath,
		"-c", filterSOPath,
		"--",
		*execFlag,
	}
	innerCmd = append(innerCmd, progArgs...)

	dockerArgs = append(dockerArgs, *imageFlag)
	dockerArgs = append(dockerArgs, innerCmd...)

	if *dryRunFlag {
		fmt.Printf("docker %s\n", strings.Join(dockerArgs, " "))
		return
	}

	fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] session=%s exec=%s timeout=%s\n",
		sessionID, *execFlag, *timeoutFlag)

	// Create a context with timeout + signal cancellation
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag+5*time.Second)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			fmt.Fprintf(os.Stderr, "\n[dynamorio-sandbox] caught %s – killing container\n", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)

	// Stream stdout/stderr
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, prefixWriter{prefix: "[sandbox] ", w: os.Stderr})

	// Use the same process group so killpg works
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] TIMEOUT after %s\n", elapsed.Round(time.Millisecond))
			os.Exit(124)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] completed in %s\n", elapsed.Round(time.Millisecond))
}

// prefixWriter is intentionally a no-op here (stdout/stderr are already streamed).
// We keep it for future per-line prefixing without allocation overhead.
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func (p prefixWriter) Write(b []byte) (int, error) {
	// No-op duplicate: stdout/stderr already streamed above.
	return len(b), nil
}
