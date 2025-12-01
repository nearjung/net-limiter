package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/shirou/gopsutil/v3/process"
)

// Constants for QoS and Firewall
const (
	qosPolicyName   = "GoNetLimit"
	firewallRuleIn  = "GoNetBlock_IN"
	firewallRuleOut = "GoNetBlock_OUT"
)

// Convert kbps to bits per second (for ThrottleRateActionBitsPerSecond)
func kbpsToBitsPerSecond(kbps int) int64 {
	if kbps <= 0 {
		return 0
	}
	// Simple conversion: 1 kbps ≈ 1000 bits per second
	return int64(kbps) * 1000
}

// Escape string for use in PowerShell
func escapeForPowerShell(s string) string {
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, `"`, "`\"")
	return s
}

// Find all PIDs for a given process name (e.g. "chrome.exe")
func findPIDsByName(target string) ([]int32, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	targetLower := strings.ToLower(target)
	var pids []int32
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		if strings.ToLower(name) == targetLower {
			pids = append(pids, p.Pid)
		}
	}
	return pids, nil
}

// Block all internet (inbound + outbound) for a given executable path
func blockInternetForProcess(exePath string) (string, error) {
	log := "Blocking internet for: " + exePath + "\n"

	script := fmt.Sprintf(`
$path = "%s"

Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName "%s" -Program $path -Direction Outbound -Action Block -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "%s" -Program $path -Direction Inbound  -Action Block -ErrorAction SilentlyContinue
`,
		escapeForPowerShell(exePath),
		firewallRuleIn, firewallRuleOut,
		firewallRuleOut, firewallRuleIn,
	)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log += "Firewall output:\n" + string(out) + "\n"
	}
	if err != nil {
		return log, fmt.Errorf("firewall error: %w", err)
	}

	log += "BlockInternet: success\n"
	return log, nil
}

// Clear QoS policy and firewall rules used by this tool
func clearAllLimits() (string, error) {
	log := "Clearing QoS policy and firewall rules...\n"

	script := fmt.Sprintf(`
Remove-NetQosPolicy    -Name "%s" -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue
`,
		qosPolicyName,
		firewallRuleIn, firewallRuleOut,
	)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log += "Output:\n" + string(out) + "\n"
	}
	if err != nil {
		return log, fmt.Errorf("clearAllLimits error: %w", err)
	}

	log += "ClearAllLimits: success\n"
	return log, nil
}

// Apply QoS throttling for a given executable path
func applyLimitForExe(exePath string, inKbps, outKbps int) (string, error) {
	log := fmt.Sprintf("Applying speed limit for: %s\n", exePath)

	// Choose the lower non-zero limit
	limitKbps := 0
	if inKbps > 0 && outKbps > 0 {
		if inKbps < outKbps {
			limitKbps = inKbps
		} else {
			limitKbps = outKbps
		}
	} else if inKbps > 0 {
		limitKbps = inKbps
	} else if outKbps > 0 {
		limitKbps = outKbps
	}

	if limitKbps <= 0 {
		return log, fmt.Errorf("limit must be > 0 to use QoS")
	}

	bitsPerSecond := kbpsToBitsPerSecond(limitKbps)
	log += fmt.Sprintf("Requested limit: %d kbps (~%d bits per second)\n", limitKbps, bitsPerSecond)

	script := fmt.Sprintf(`
Remove-NetQosPolicy -Name "%s" -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue

New-NetQosPolicy -Name "%s" -AppPathNameMatchCondition "%s" -ThrottleRateActionBitsPerSecond %d -PolicyStore ActiveStore
`,
		qosPolicyName,
		qosPolicyName,
		escapeForPowerShell(exePath),
		bitsPerSecond,
	)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log += "QoS output:\n" + string(out) + "\n"
	}
	if err != nil {
		return log, fmt.Errorf("QoS error: %w", err)
	}

	log += "ApplyLimit: success\n"
	return log, nil
}

func main() {
	application := app.New()
	window := application.NewWindow("Windows NetLimiter GUI")
	window.Resize(fyne.NewSize(600, 480))

	processEntry := widget.NewEntry()
	processEntry.SetPlaceHolder("Process name, e.g. chrome.exe")

	inEntry := widget.NewEntry()
	inEntry.SetPlaceHolder("Limit IN (kbps), 0 for block if both are 0")

	outEntry := widget.NewEntry()
	outEntry.SetPlaceHolder("Limit OUT (kbps), 0 for block if both are 0")

	logArea := widget.NewMultiLineEntry()
	logArea.SetPlaceHolder("Log output...")
	logArea.Wrapping = fyne.TextWrapWord
	logArea.SetMinRowsVisible(12)

	// Safe log appender from any goroutine, using fyne.Do (Driver.DoFromGoroutine)
	appendLog := func(text string) {
		fyne.Do(func() {
			logArea.SetText(logArea.Text + text + "\n")
		})
	}

	applyButton := widget.NewButton("Apply Limit / Block", func() {
		// Run heavy work in a goroutine to avoid freezing the UI
		go func() {
			appendLog("----------------------------------------------------")

			procName := strings.TrimSpace(processEntry.Text)
			if procName == "" {
				appendLog("Error: process name is required")
				return
			}

			// Parse IN / OUT limits
			parseInt := func(s string) (int, error) {
				s = strings.TrimSpace(s)
				if s == "" {
					return 0, nil
				}
				return strconv.Atoi(s)
			}

			inKbps, err := parseInt(inEntry.Text)
			if err != nil {
				appendLog("Error: Limit IN must be an integer")
				return
			}
			outKbps, err := parseInt(outEntry.Text)
			if err != nil {
				appendLog("Error: Limit OUT must be an integer")
				return
			}

			// Find process
			pids, err := findPIDsByName(procName)
			if err != nil {
				appendLog("Error finding process: " + err.Error())
				return
			}
			if len(pids) == 0 {
				appendLog("No process found with name: " + procName)
				return
			}

			p, err := process.NewProcess(pids[0])
			if err != nil {
				appendLog("Error reading process info: " + err.Error())
				return
			}
			exePath, err := p.Exe()
			if err != nil || exePath == "" {
				appendLog("Could not get executable path for process")
				return
			}

			appendLog("Process path: " + exePath)

			// Clear previous rules/policies
			if clearLog, err := clearAllLimits(); err != nil {
				appendLog(clearLog)
				appendLog("ClearAllLimits error: " + err.Error())
			} else {
				appendLog(clearLog)
			}

			// If both IN and OUT are 0: block internet
			if inKbps == 0 && outKbps == 0 {
				blockLog, err := blockInternetForProcess(exePath)
				appendLog(blockLog)
				if err != nil {
					appendLog("BlockInternet error: " + err.Error())
				}
			} else {
				// Otherwise: apply QoS limit
				limitLog, err := applyLimitForExe(exePath, inKbps, outKbps)
				appendLog(limitLog)
				if err != nil {
					appendLog("ApplyLimit error: " + err.Error())
				}
			}
		}()
	})

	clearLimitButton := widget.NewButton("Clear Limit", func() {
		// Run in goroutine as it calls PowerShell too
		go func() {
			logText, err := clearAllLimits()
			appendLog("----------------------------------------------------")
			appendLog(logText)
			if err != nil {
				appendLog("ClearAllLimits error: " + err.Error())
			}
		}()
	})

	clearLogButton := widget.NewButton("Clear Log", func() {
		fyne.Do(func() {
			logArea.SetText("")
		})
	})

	form := container.NewVBox(
		widget.NewLabel("Windows NetLimiter (GUI)"),
		widget.NewLabel("Run this program as Administrator."),
		widget.NewSeparator(),
		widget.NewForm(
			widget.NewFormItem("Process Name", processEntry),
			widget.NewFormItem("Limit IN (kbps)", inEntry),
			widget.NewFormItem("Limit OUT (kbps)", outEntry),
		),
		container.NewHBox(applyButton, clearLimitButton, clearLogButton),
		widget.NewSeparator(),
		widget.NewLabel("Log:"),
		logArea,
	)

	window.SetContent(form)
	window.ShowAndRun()
}
