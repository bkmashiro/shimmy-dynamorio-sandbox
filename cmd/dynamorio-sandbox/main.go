// cmd/dynamorio-sandbox/main.go
//
// Go wrapper that spawns a Docker container running an arbitrary command
// under DynamoRIO syscall filtering.
//
// Usage:
//   go run ./cmd/dynamorio-sandbox/ -- <command> [args...]
//   go run ./cmd/dynamorio-sandbox/ --image myimage -- /app/myprogram
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultImage  = "dynamorio-sandbox-demo"
	dynamorioHome = "/opt/dynamorio"
	clientSO      = "/sandbox/syscall_filter.so"
)

func usage() {
	fmt.Fprintf(os.Stderr, `dynamorio-sandbox: run a command under DynamoRIO syscall filtering

Usage:
  dynamorio-sandbox [flags] -- <command> [args...]

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  dynamorio-sandbox -- ./test_open
  dynamorio-sandbox --image my-app -- /usr/bin/myprogram
  dynamorio-sandbox --dry-run -- /bin/cat /etc/hosts
`)
}

func main() {
	image := flag.String("image", defaultImage, "Docker image to use")
	dryRun := flag.Bool("dry-run", false, "Print docker command without executing")
	memory := flag.String("memory", "256m", "Container memory limit")
	cpus := flag.String("cpus", "1", "Container CPU limit")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: no command specified")
		flag.Usage()
		os.Exit(1)
	}

	// Find the repo root to mount the client .so
	scriptDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		scriptDir = "."
	}
	// Walk up to find proto-d-dynamorio directory
	protoDir := findProtoDir(scriptDir)

	// Build drrun command: drrun -c <client.so> -- <cmd> [args...]
	drrunArgs := []string{
		"drrun",
		"-c", clientSO,
		"--",
	}
	drrunArgs = append(drrunArgs, args...)

	// Build docker run command
	dockerArgs := []string{
		"docker", "run",
		"--rm",
		"--memory", *memory,
		"--cpus", *cpus,
		// No --privileged, no --cap-add SYS_PTRACE needed!
		"--security-opt", "no-new-privileges",
	}

	// Mount client .so if available locally
	clientSOLocal := filepath.Join(protoDir, "syscall_filter.so")
	if _, err := os.Stat(clientSOLocal); err == nil {
		dockerArgs = append(dockerArgs,
			"-v", fmt.Sprintf("%s:%s:ro", clientSOLocal, clientSO))
	}

	dockerArgs = append(dockerArgs, *image)
	dockerArgs = append(dockerArgs, drrunArgs...)

	fmt.Printf("[dynamorio-sandbox] Running under DynamoRIO syscall filter\n")
	fmt.Printf("[dynamorio-sandbox] Image: %s\n", *image)
	fmt.Printf("[dynamorio-sandbox] Command: %s\n", strings.Join(args, " "))
	fmt.Printf("[dynamorio-sandbox] Docker: %s\n\n", strings.Join(dockerArgs, " "))

	if *dryRun {
		fmt.Println("[dynamorio-sandbox] Dry run - not executing")
		return
	}

	cmd := exec.Command(dockerArgs[0], dockerArgs[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "[dynamorio-sandbox] error: %v\n", err)
		os.Exit(1)
	}
}

// findProtoDir walks up from dir to find the proto-d-dynamorio directory.
func findProtoDir(dir string) string {
	for {
		candidate := filepath.Join(dir, "syscall_filter.c")
		if _, err := os.Stat(candidate); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}
