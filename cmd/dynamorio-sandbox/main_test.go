package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseCLIUsesPositionalCommandAfterDoubleDash(t *testing.T) {
	cfg, err := parseCLI([]string{"--mode", "observe", "--", "/bin/sh", "-c", "printf hi"})
	if err != nil {
		t.Fatalf("parseCLI returned error: %v", err)
	}
	if cfg.Exec != "/bin/sh" {
		t.Fatalf("Exec = %q, want /bin/sh", cfg.Exec)
	}
	wantArgs := []string{"-c", "printf hi"}
	if !reflect.DeepEqual(cfg.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", cfg.Args, wantArgs)
	}
	if cfg.Verbose {
		t.Fatalf("Verbose default = true, want false for transparent stdout/stderr")
	}
}

func TestParseCLIKeepsLegacyExecArgs(t *testing.T) {
	cfg, err := parseCLI([]string{"--exec", "/bin/echo", "--args", "hello world", "--timeout", "3s"})
	if err != nil {
		t.Fatalf("parseCLI returned error: %v", err)
	}
	if cfg.Exec != "/bin/echo" {
		t.Fatalf("Exec = %q, want /bin/echo", cfg.Exec)
	}
	wantArgs := []string{"hello", "world"}
	if !reflect.DeepEqual(cfg.Args, wantArgs) {
		t.Fatalf("Args = %#v, want %#v", cfg.Args, wantArgs)
	}
	if cfg.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %s, want 3s", cfg.Timeout)
	}
}

func TestLoadPolicyFileMergesEnvWithoutChangingCommand(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "policy-*.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("# evaluator policy\nDR_NETWORK_POLICY=allow:127.0.0.1:9;block:*\nDR_MAX_ALLOC_BYTES=256m\n\n")
	_ = f.Close()

	cfg, err := parseCLI([]string{"--policy-file", f.Name(), "--", "/usr/bin/evaluator", "case1"})
	if err != nil {
		t.Fatalf("parseCLI returned error: %v", err)
	}
	if cfg.Exec != "/usr/bin/evaluator" || !reflect.DeepEqual(cfg.Args, []string{"case1"}) {
		t.Fatalf("command drifted after loading policy: exec=%q args=%#v", cfg.Exec, cfg.Args)
	}
	if got := cfg.Env["DR_NETWORK_POLICY"]; got != "allow:127.0.0.1:9;block:*" {
		t.Fatalf("DR_NETWORK_POLICY = %q", got)
	}
	if got := cfg.Env["DR_MAX_ALLOC_BYTES"]; got != "256m" {
		t.Fatalf("DR_MAX_ALLOC_BYTES = %q", got)
	}
}

func TestBuildDockerArgsUsesExactCommandAndPolicyEnv(t *testing.T) {
	cfg := sandboxConfig{
		Exec:        "/bin/sh",
		Args:        []string{"-c", "printf hi"},
		Timeout:     2 * time.Second,
		Image:       "dynamorio-sandbox",
		SessionID:   "test-session",
		Mode:        "observe",
		RedirectTmp: true,
		Workdir:     "/workspace/evaluator",
		EvaluatorEnv: map[string]string{
			"EVALUATOR_MARK": "ok",
		},
		Env: map[string]string{
			"DR_AUDIT_PATH":     "/tmp/audit.jsonl",
			"DR_NETWORK_POLICY": "block:*",
		},
	}
	args := buildDockerArgs(cfg)
	if indexOf(args, "-i") < 0 {
		t.Fatalf("docker args must include -i so evaluator stdin is transparent: %#v", args)
	}
	joined := strings.Join(args, "\x00")
	for _, want := range []string{"DR_AUDIT_PATH=/tmp/audit.jsonl", "DR_NETWORK_POLICY=block:*", "EVALUATOR_MARK=ok", "/workspace/evaluator:/workspace/evaluator", drrunPath, filterSOPath, "/bin/sh", "printf hi"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker args missing %q: %#v", want, args)
		}
	}
	imageIndex := indexOf(args, "dynamorio-sandbox")
	drrunIndex := indexOf(args, drrunPath)
	cmdIndex := indexOf(args, "/bin/sh")
	if !(imageIndex >= 0 && imageIndex < drrunIndex && drrunIndex < cmdIndex) {
		t.Fatalf("bad command ordering: image=%d drrun=%d cmd=%d args=%#v", imageIndex, drrunIndex, cmdIndex, args)
	}
}

func indexOf(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}
