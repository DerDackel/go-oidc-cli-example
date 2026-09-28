package auth

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowser starts the default browser for rawURL. The command is not waited
// for, so the CLI keeps listening on the redirect URI. It is a variable so the
// tests can drive the flow without a real browser.
var openBrowser = func(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		return fmt.Errorf("no known browser command for %s", runtime.GOOS)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the child once it exits instead of leaving a zombie behind.
	go func() { _ = cmd.Wait() }()
	return nil
}
