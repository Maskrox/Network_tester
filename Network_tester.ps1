<#
.SYNOPSIS
    Enterprise Network Master Tool - Universal Connectivity Diagnostics Suite.
    
.DESCRIPTION
    A comprehensive GUI-based tool designed for IT Administrators and Network Engineers.
    Includes advanced DNS resolution (Aliases/CNAMEs), TCP Socket testing, and 
    Layer 7 HTTP Proxy simulation.

.NOTES
    Version:        2.3 (Resizable / Full Screen Support)
    Requirements:   PowerShell 5.1+, .NET Framework 4.5+
    License:        MIT (Open Source)
#>

# Load Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# SECURITY: Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# =============================================================================
# MAIN FORM SETUP
# =============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enterprise Network Master Tool v2.3"
$form.Size = New-Object System.Drawing.Size(1000, 800)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
$form.ForeColor = "WhiteSmoke"
# FIX: Allow Resizing
$form.FormBorderStyle = "Sizable" 
$form.MaximizeBox = $true
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

# --- TYPOGRAPHY ---
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontLabel = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$fontInput = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
$fontLog   = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)

# =============================================================================
# SECTION 1: TARGET CONFIGURATION (Left Panel - Fixed)
# =============================================================================
$grpTargets = New-Object System.Windows.Forms.GroupBox
$grpTargets.Text = " 1. Target Configuration "
$grpTargets.Location = New-Object System.Drawing.Point(15, 15)
$grpTargets.Size = New-Object System.Drawing.Size(340, 260)
$grpTargets.ForeColor = "Cyan"
$grpTargets.Font = $fontTitle
# Anchor Top-Left (Standard)
$grpTargets.Anchor = "Top, Left"
$form.Controls.Add($grpTargets)

    $lblTargets = New-Object System.Windows.Forms.Label
    $lblTargets.Text = "Hostname or URL List:"
    $lblTargets.Location = New-Object System.Drawing.Point(15, 30)
    $lblTargets.AutoSize = $true
    $lblTargets.ForeColor = "White"
    $lblTargets.Font = $fontLabel
    $grpTargets.Controls.Add($lblTargets)

    $txtTargets = New-Object System.Windows.Forms.TextBox
    $txtTargets.Multiline = $true
    $txtTargets.ScrollBars = "Vertical"
    $txtTargets.Location = New-Object System.Drawing.Point(15, 55)
    $txtTargets.Size = New-Object System.Drawing.Size(310, 140)
    $txtTargets.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $txtTargets.ForeColor = "White"
    $txtTargets.Font = $fontInput
    $txtTargets.Text = "google.com`nmicrosoft.com`ncloudflare.com`n1.1.1.1"
    $grpTargets.Controls.Add($txtTargets)

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "TCP Port (For Telnet Test):"
    $lblPort.Location = New-Object System.Drawing.Point(15, 215)
    $lblPort.AutoSize = $true
    $lblPort.Font = $fontLabel
    $grpTargets.Controls.Add($lblPort)

    $txtPort = New-Object System.Windows.Forms.TextBox
    $txtPort.Location = New-Object System.Drawing.Point(220, 212)
    $txtPort.Size = New-Object System.Drawing.Size(105, 26)
    $txtPort.Text = "443"
    $txtPort.Font = $fontInput
    $txtPort.TextAlign = "Center"
    $grpTargets.Controls.Add($txtPort)

# =============================================================================
# SECTION 2: PROXY STRATEGY (Left Panel - Fixed)
# =============================================================================
$grpProxy = New-Object System.Windows.Forms.GroupBox
$grpProxy.Text = " 2. Proxy Strategy "
$grpProxy.Location = New-Object System.Drawing.Point(15, 290)
$grpProxy.Size = New-Object System.Drawing.Size(340, 220)
$grpProxy.ForeColor = "Yellow"
$grpProxy.Font = $fontTitle
$grpProxy.Anchor = "Top, Left"
$form.Controls.Add($grpProxy)

    $rbPac = New-Object System.Windows.Forms.RadioButton
    $rbPac.Text = "System / PAC Script (Auto-Detect)"
    $rbPac.Location = New-Object System.Drawing.Point(20, 30)
    $rbPac.Size = New-Object System.Drawing.Size(300, 25)
    $rbPac.ForeColor = "White"
    $rbPac.Font = $fontLabel
    $rbPac.Checked = $false
    $grpProxy.Controls.Add($rbPac)

    $rbManual = New-Object System.Windows.Forms.RadioButton
    $rbManual.Text = "Manual Configuration:"
    $rbManual.Location = New-Object System.Drawing.Point(20, 65)
    $rbManual.Size = New-Object System.Drawing.Size(300, 25)
    $rbManual.ForeColor = "White"
    $rbManual.Font = $fontLabel
    $grpProxy.Controls.Add($rbManual)

    $txtProxyAddr = New-Object System.Windows.Forms.TextBox
    $txtProxyAddr.Location = New-Object System.Drawing.Point(40, 95)
    $txtProxyAddr.Size = New-Object System.Drawing.Size(200, 26)
    $txtProxyAddr.Text = ""
    $txtProxyAddr.Font = $fontInput
    $grpProxy.Controls.Add($txtProxyAddr)

    $txtProxyPort = New-Object System.Windows.Forms.TextBox
    $txtProxyPort.Location = New-Object System.Drawing.Point(250, 95)
    $txtProxyPort.Size = New-Object System.Drawing.Size(75, 26)
    $txtProxyPort.Text = "8080"
    $txtProxyPort.Font = $fontInput
    $grpProxy.Controls.Add($txtProxyPort)

    $rbNoProxy = New-Object System.Windows.Forms.RadioButton
    $rbNoProxy.Text = "No Proxy (Direct Access)"
    $rbNoProxy.Location = New-Object System.Drawing.Point(20, 140)
    $rbNoProxy.Size = New-Object System.Drawing.Size(300, 25)
    $rbNoProxy.ForeColor = "Silver"
    $rbNoProxy.Font = $fontLabel
    $rbNoProxy.Checked = $true
    $grpProxy.Controls.Add($rbNoProxy)

# =============================================================================
# SECTION 3: EXECUTION CONTROLS (Left Panel - Fixed)
# =============================================================================
$grpActions = New-Object System.Windows.Forms.GroupBox
$grpActions.Text = " 3. Execute Diagnostics "
$grpActions.Location = New-Object System.Drawing.Point(15, 520)
$grpActions.Size = New-Object System.Drawing.Size(340, 230)
$grpActions.ForeColor = "LightGreen"
$grpActions.Font = $fontTitle
$grpActions.Anchor = "Top, Left"
$form.Controls.Add($grpActions)

    # Button DNS
    $btnDNS = New-Object System.Windows.Forms.Button
    $btnDNS.Text = "Test 1: DNS Lookup (Full Info)"
    $btnDNS.Location = New-Object System.Drawing.Point(20, 30)
    $btnDNS.Size = New-Object System.Drawing.Size(300, 35)
    $btnDNS.BackColor = "DimGray"
    $btnDNS.ForeColor = "White"
    $btnDNS.FlatStyle = "Flat"
    $btnDNS.Font = $fontLabel
    $grpActions.Controls.Add($btnDNS)

    # Button Ping
    $btnPing = New-Object System.Windows.Forms.Button
    $btnPing.Text = "Test 2: ICMP Ping"
    $btnPing.Location = New-Object System.Drawing.Point(20, 75)
    $btnPing.Size = New-Object System.Drawing.Size(300, 35)
    $btnPing.BackColor = "DimGray"
    $btnPing.ForeColor = "White"
    $btnPing.FlatStyle = "Flat"
    $btnPing.Font = $fontLabel
    $grpActions.Controls.Add($btnPing)

    # Button TCP
    $btnTCP = New-Object System.Windows.Forms.Button
    $btnTCP.Text = "Test 3: TCP Socket (Firewall Check)"
    $btnTCP.Location = New-Object System.Drawing.Point(20, 120)
    $btnTCP.Size = New-Object System.Drawing.Size(300, 35)
    $btnTCP.BackColor = "DimGray"
    $btnTCP.ForeColor = "White"
    $btnTCP.FlatStyle = "Flat"
    $btnTCP.Font = $fontLabel
    $grpActions.Controls.Add($btnTCP)

    # Button HTTP
    $btnHTTP = New-Object System.Windows.Forms.Button
    $btnHTTP.Text = "Test 4: HTTP / PROXY (Layer 7)"
    $btnHTTP.Location = New-Object System.Drawing.Point(20, 165)
    $btnHTTP.Size = New-Object System.Drawing.Size(300, 45)
    $btnHTTP.BackColor = "SeaGreen"
    $btnHTTP.ForeColor = "White"
    $btnHTTP.FlatStyle = "Flat"
    $btnHTTP.Font = [System.Drawing.Font]::new("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $grpActions.Controls.Add($btnHTTP)

# =============================================================================
# SECTION 4: OUTPUT LOGS (Right Panel - Resizable)
# =============================================================================
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = " Diagnostic Output "
$grpLog.Location = New-Object System.Drawing.Point(370, 15)
$grpLog.Size = New-Object System.Drawing.Size(600, 735)
$grpLog.ForeColor = "White"
$grpLog.Font = $fontTitle
# FIX: Anchor to all sides so it stretches
$grpLog.Anchor = "Top, Bottom, Left, Right"
$form.Controls.Add($grpLog)

    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Location = New-Object System.Drawing.Point(15, 30)
    $rtbLog.Size = New-Object System.Drawing.Size(570, 650)
    $rtbLog.BackColor = "Black"
    $rtbLog.ForeColor = "LightGray"
    $rtbLog.Font = $fontLog
    $rtbLog.ReadOnly = $true
    # FIX: Stretch content inside
    $rtbLog.Anchor = "Top, Bottom, Left, Right"
    $grpLog.Controls.Add($rtbLog)
    
    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = "Clear Log Window"
    $btnClear.Location = New-Object System.Drawing.Point(15, 690)
    $btnClear.Size = New-Object System.Drawing.Size(570, 30)
    $btnClear.BackColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    $btnClear.ForeColor = "White"
    $btnClear.FlatStyle = "Flat"
    $btnClear.Font = $fontLabel
    # FIX: Stick to bottom
    $btnClear.Anchor = "Bottom, Left, Right"
    $grpLog.Controls.Add($btnClear)

# =============================================================================
# LOGIC CORE
# =============================================================================

function Log-Write ($text, $color) {
    $rtbLog.SelectionStart = $rtbLog.TextLength
    $rtbLog.SelectionLength = 0
    $rtbLog.SelectionColor = $color
    $rtbLog.AppendText($text + "`r`n")
    $rtbLog.ScrollToCaret()
    $form.Refresh()
}

# --- EVENT HANDLER DNS (Full) ---
$btnDNS.Add_Click({
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING FULL DNS LOOKUP" "Cyan"
    
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        
        Log-Write "Querying: $t ..." "White"
        try {
            $entry = [System.Net.Dns]::GetHostEntry($t)
            
            Log-Write "  [NAME]  $($entry.HostName)" "Lime"
            
            if ($entry.Aliases) {
                foreach ($alias in $entry.Aliases) {
                    Log-Write "  [ALIAS] $alias" "Yellow"
                }
            }
            
            foreach ($ip in $entry.AddressList) {
                Log-Write "  [IP]    $($ip.IPAddressToString)" "Gray"
            }
        } catch { 
            Log-Write "  [DNS FAIL] Host not found / No records." "Red" 
        }
    }
})

# --- EVENT HANDLER PING ---
$btnPing.Add_Click({
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING ICMP PING TEST" "Cyan"
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        Log-Write "Pinging $t ..." "White"
        try {
            $ping = Test-Connection -ComputerName $t -Count 1 -ErrorAction SilentlyContinue
            if ($ping) { Log-Write "  [ALIVE] Reply from $($ping.IPV4Address)" "Green" }
            else { Log-Write "  [NO REPLY] Timeout (Firewall blocked?)" "Orange" }
        } catch { Log-Write "  [ERROR] Invalid Hostname." "Red" }
    }
})

# --- EVENT HANDLER TCP ---
$btnTCP.Add_Click({
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING TCP PORT TEST (Bypassing Proxy)" "Cyan"
    $port = $txtPort.Text
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        Log-Write "Connecting to $t : $port ..." "White"
        try {
            $tcp = Test-NetConnection -ComputerName $t -Port $port -InformationLevel Quiet
            if ($tcp) { Log-Write "  [OPEN] Connection Established." "Green" }
            else { Log-Write "  [CLOSED] Connection Refused/Filtered." "Red" }
        } catch { Log-Write "  [ERROR] DNS/Network Unreachable." "Red" }
    }
})

# --- EVENT HANDLER HTTP ---
$btnHTTP.Add_Click({
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING HTTP PROXY TEST (Layer 7)" "Cyan"
    
    try {
        if ($rbPac.Checked) {
            Log-Write "Strategy: SYSTEM / PAC (Auto-Detect)" "Yellow"
            $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $sysProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
            [System.Net.WebRequest]::DefaultWebProxy = $sysProxy
        } elseif ($rbManual.Checked) {
            if ([string]::IsNullOrWhiteSpace($txtProxyAddr.Text)) {
                Log-Write "Error: Proxy Address empty." "Red"; return
            }
            $p = "http://" + $txtProxyAddr.Text + ":" + $txtProxyPort.Text
            Log-Write "Strategy: MANUAL PROXY ($p)" "Yellow"
            $wp = New-Object System.Net.WebProxy($p)
            $wp.UseDefaultCredentials = $true
            [System.Net.WebRequest]::DefaultWebProxy = $wp
        } else {
            Log-Write "Strategy: DIRECT ACCESS" "Magenta"
            [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        }
    } catch { Log-Write "Proxy Config Error: $($_.Exception.Message)" "Red"; return }

    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        $t = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if (-not ($t -match "^http")) { $t = "https://" + $t }
        
        Log-Write "Requesting: $t" "White"
        try {
            $req = Invoke-WebRequest -Uri $t -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
            Log-Write "  [SUCCESS] 200 OK - Full Access." "Green"
        } catch {
            $ex = $_.Exception
            if ($ex.Response) {
                $c = [int]$ex.Response.StatusCode
                if ($c -eq 404 -or $c -eq 403) {
                    Log-Write "  [CONNECTED] Reached Server (Code $c)." "Lime"
                } elseif ($c -eq 407) {
                    Log-Write "  [BLOCKED] Proxy Auth Required (407)." "Red"
                } else {
                    Log-Write "  [WARNING] Server Code $c" "Orange"
                }
            } else {
                Log-Write "  [FAIL] Unreachable." "Red"
            }
        }
    }
})

$btnClear.Add_Click({ $rtbLog.Clear() })

# --- LAUNCH ---
$form.ShowDialog()
