# Windows NetLimiter GUI (Go + Fyne)

A lightweight Windows application that can **limit or block internet access per process** using PowerShell.  
Built with **Go** and **Fyne**, this tool provides a simple GUI for controlling network bandwidth or fully blocking connections for any running executable.

This application requires **Administrator privileges** in order to manage Windows Firewall and QoS policies.

---

## Features

- Limit network speed (in kbps) for any process.
- Block all inbound and outbound internet traffic for a specific process.
- Automatically detects the executable path from a process name.
- Built-in GUI using Fyne v2.
- Non-blocking UI (PowerShell execution runs in background goroutines).
- Clear previous limits (QoS + Firewall rules).
- Clear log output with one click.

---

## How It Works

### Bandwidth Limiting  
Uses **Windows QoS (Quality of Service)** via PowerShell:

```powershell
New-NetQosPolicy -Name "GoNetLimit" -AppPathNameMatchCondition "<exe>" \
  -ThrottleRateActionBitsPerSecond <bitsPerSecond>
