<#
.SYNOPSIS
    Enterprise Network Master Tool v3.0 - Universal Diagnostics Suite.
    
.DESCRIPTION
    The ultimate connectivity troubleshooting tool for Enterprise Environments.
    
    FEATURES:
    - Layer 1-7 Testing: ICMP, TCP Socket, DNS, and HTTP/Proxy.
    - SSL INSPECTION: Checks certificate expiration dates and Issuer (Man-in-the-Middle detection).
    - REPORTING: Export logs to timestamped text files.
    - COMPATIBILITY: High-DPI support, Resizable Window, TLS 1.2 Enforcement.
    - PROXY SUPPORT: Auto-detect (PAC), Manual, and Direct modes.

.NOTES
    Version:        3.0 (Master Edition)
    Requirements:   PowerShell 5.1+, .NET Framework 4.5+
    Author:         [Your Name/Handle]
    License:        MIT
#>

# Load Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# SECURITY: Force TLS 1.2 (Mandatory for modern cloud connectivity)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# =============================================================================
# MAIN FORM SETUP
# =============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enterprise Network Master Tool v3.0"
$form.Size = New-Object System.Drawing.Size(1100, 850)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
$form.ForeColor = "WhiteSmoke"
$form.FormBorderStyle = "Sizable"
$form.MaximizeBox = $true
$form.AutoScroll = $true
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

# --- TYPOGRAPHY ---
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontLabel = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$fontInput = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)
$fontLog   = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)

# =============================================================================
# SECTION 1: TARGET CONFIGURATION (Left Panel)
# =============================================================================
$grpTargets = New-Object System.Windows.Forms.GroupBox
$grpTargets.Text = " 1. Target Configuration "
$grpTargets.Location = New-Object System.Drawing.Point(15, 15)
$grpTargets.Size = New-Object System.Drawing.Size(350, 260)
$grpTargets.ForeColor = "Cyan"
$grpTargets.Font = $fontTitle
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
    $txtTargets.Size = New-Object System.Drawing.Size(320, 140)
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
    $txtPort.Location = New-Object System.Drawing.Point(230, 212)
    $txtPort.Size = New-Object System.Drawing.Size(95, 26)
    $txtPort.Text = "443"
    $txtPort.Font = $fontInput
    $txtPort.TextAlign = "Center"
    $grpTargets.Controls.Add($txtPort)

# =============================================================================
# SECTION 2: PROXY STRATEGY (Left Panel)
# =============================================================================
$grpProxy = New-Object System.Windows.Forms.GroupBox
$grpProxy.Text = " 2. Proxy Strategy "
$grpProxy.Location = New-Object System.Drawing.Point(15, 290)
$grpProxy.Size = New-Object System.Drawing.Size(350, 220)
$grpProxy.ForeColor = "Yellow"
$grpProxy.Font = $fontTitle
$grpProxy.Anchor = "Top, Left"
$form.Controls.Add($grpProxy)

    $rbPac = New-Object System.Windows.Forms.RadioButton
    $rbPac.Text = "System / PAC Script (Auto-Detect)"
    $rbPac.Location = New-Object System.Drawing.Point(20, 30)
    $rbPac.Size = New-Object System.Drawing.Size(310, 25)
    $rbPac.ForeColor = "White"
    $rbPac.Font = $fontLabel
    $rbPac.Checked = $false
    $grpProxy.Controls.Add($rbPac)

    $rbManual = New-Object System.Windows.Forms.RadioButton
    $rbManual.Text = "Manual Configuration:"
    $rbManual.Location = New-Object System.Drawing.Point(20, 65)
    $rbManual.Size = New-Object System.Drawing.Size(310, 25)
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
    $rbNoProxy.Size = New-Object System.Drawing.Size(310, 25)
    $rbNoProxy.ForeColor = "Silver"
    $rbNoProxy.Font = $fontLabel
    $rbNoProxy.Checked = $true
    $grpProxy.Controls.Add($rbNoProxy)

# =============================================================================
# SECTION 3: EXECUTION CONTROLS (AUTO-LAYOUT)
# =============================================================================
$grpActions = New-Object System.Windows.Forms.GroupBox
$grpActions.Text = " 3. Execute Diagnostics "
$grpActions.Location = New-Object System.Drawing.Point(15, 520)
$grpActions.Size = New-Object System.Drawing.Size(350, 310) # Increased height for SSL button
$grpActions.ForeColor = "LightGreen"
$grpActions.Font = $fontTitle
$grpActions.Anchor = "Top, Left"
$form.Controls.Add($grpActions)

    # Use FlowLayoutPanel for auto-stacking buttons
    $flowPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowPanel.Dock = "Fill"
    $flowPanel.FlowDirection = "TopDown"
    $flowPanel.WrapContents = $false
    $flowPanel.AutoScroll = $true 
    $flowPanel.Padding = New-Object System.Windows.Forms.Padding(10)
    $grpActions.Controls.Add($flowPanel)

    # 1. DNS
    $btnDNS = New-Object System.Windows.Forms.Button
    $btnDNS.Text = "Test 1: DNS Lookup (Full Info)"
    $btnDNS.Size = New-Object System.Drawing.Size(310, 40)
    $btnDNS.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    $btnDNS.BackColor = "DimGray"
    $btnDNS.ForeColor = "White"
    $btnDNS.FlatStyle = "Flat"
    $btnDNS.Font = $fontLabel
    $flowPanel.Controls.Add($btnDNS)

    # 2. Ping
    $btnPing = New-Object System.Windows.Forms.Button
    $btnPing.Text = "Test 2: ICMP Ping"
    $btnPing.Size = New-Object System.Drawing.Size(310, 40)
    $btnPing.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    $btnPing.BackColor = "DimGray"
    $btnPing.ForeColor = "White"
    $btnPing.FlatStyle = "Flat"
    $btnPing.Font = $fontLabel
    $flowPanel.Controls.Add($btnPing)

    # 3. TCP
    $btnTCP = New-Object System.Windows.Forms.Button
    $btnTCP.Text = "Test 3: TCP Socket (Firewall Check)"
    $btnTCP.Size = New-Object System.Drawing.Size(310, 40)
    $btnTCP.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    $btnTCP.BackColor = "DimGray"
    $btnTCP.ForeColor = "White"
    $btnTCP.FlatStyle = "Flat"
    $btnTCP.Font = $fontLabel
    $flowPanel.Controls.Add($btnTCP)

    # 4. HTTP
    $btnHTTP = New-Object System.Windows.Forms.Button
    $btnHTTP.Text = "Test 4: HTTP / PROXY (Layer 7)"
    $btnHTTP.Size = New-Object System.Drawing.Size(310, 45)
    $btnHTTP.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    $btnHTTP.BackColor = "SeaGreen"
    $btnHTTP.ForeColor = "White"
    $btnHTTP.FlatStyle = "Flat"
    $btnHTTP.Font = [System.Drawing.Font]::new("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $flowPanel.Controls.Add($btnHTTP)

    # 5. SSL (NEW)
    $btnSSL = New-Object System.Windows.Forms.Button
    $btnSSL.Text = "Test 5: SSL Expiration Check"
    $btnSSL.Size = New-Object System.Drawing.Size(310, 40)
    $btnSSL.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
    $btnSSL.BackColor = "Purple" # Distinct color
    $btnSSL.ForeColor = "White"
    $btnSSL.FlatStyle = "Flat"
    $btnSSL.Font = $fontLabel
    $flowPanel.Controls.Add($btnSSL)

# =============================================================================
# SECTION 4: OUTPUT LOGS (Right Panel)
# =============================================================================
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = " Diagnostic Output "
$grpLog.Location = New-Object System.Drawing.Point(380, 15)
$grpLog.Size = New-Object System.Drawing.Size(690, 815)
$grpLog.ForeColor = "White"
$grpLog.Font = $fontTitle
$grpLog.Anchor = "Top, Bottom, Left, Right"
$form.Controls.Add($grpLog)

    # RichTextBox
    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Location = New-Object System.Drawing.Point(15, 30)
    $rtbLog.Size = New-Object System.Drawing.Size(660, 730)
    $rtbLog.BackColor = "Black"
    $rtbLog.ForeColor = "LightGray"
    $rtbLog.Font = $fontLog
    $rtbLog.ReadOnly = $true
    $rtbLog.Anchor = "Top, Bottom, Left, Right"
    $grpLog.Controls.Add($rtbLog)
    
    # Button Clear (Left)
    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = "Clear Logs"
    $btnClear.Location = New-Object System.Drawing.Point(15, 770)
    $btnClear.Size = New-Object System.Drawing.Size(320, 35)
    $btnClear.BackColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    $btnClear.ForeColor = "White"
    $btnClear.FlatStyle = "Flat"
    $btnClear.Font = $fontLabel
    $btnClear.Anchor = "Bottom, Left"
    $grpLog.Controls.Add($btnClear)

    # Button Save (Right) - NEW
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "💾 Export Report to File"
    $btnSave.Location = New-Object System.Drawing.Point(350, 770)
    $btnSave.Size = New-Object System.Drawing.Size(325, 35)
    $btnSave.BackColor = "DimGray"
    $btnSave.ForeColor = "White"
    $btnSave.FlatStyle = "Flat"
    $btnSave.Font = $fontLabel
    $btnSave.Anchor = "Bottom, Right"
    $grpLog.Controls.Add($btnSave)

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

# --- EVENT: DNS ---
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
            if ($entry.Aliases) { foreach ($alias in $entry.Aliases) { Log-Write "  [ALIAS] $alias" "Yellow" } }
            foreach ($ip in $entry.AddressList) { Log-Write "  [IP]    $($ip.IPAddressToString)" "Gray" }
        } catch { Log-Write "  [DNS FAIL] Host not found / No records." "Red" }
    }
})

# --- EVENT: PING ---
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

# --- EVENT: TCP ---
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

# --- EVENT: HTTP ---
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
            if ([string]::IsNullOrWhiteSpace($txtProxyAddr.Text)) { Log-Write "Error: Proxy Address empty." "Red"; return }
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
                if ($c -eq 404 -or $c -eq 403) { Log-Write "  [CONNECTED] Reached Server (Code $c)." "Lime" }
                elseif ($c -eq 407) { Log-Write "  [BLOCKED] Proxy Auth Required (407)." "Red" }
                else { Log-Write "  [WARNING] Server Code $c" "Orange" }
            } else { Log-Write "  [FAIL] Unreachable." "Red" }
        }
    }
})

# --- EVENT: SSL ---
$btnSSL.Add_Click({
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING SSL CERTIFICATE INSPECTION" "Cyan"
    
    # Configure Proxy for SSL Request
    $proxyObj = $null
    if ($rbPac.Checked) { 
        $proxyObj = [System.Net.WebRequest]::GetSystemWebProxy()
        $proxyObj.Credentials = [System.Net.CredentialCache]::DefaultCredentials 
    } elseif ($rbManual.Checked) { 
        if (-not [string]::IsNullOrWhiteSpace($txtProxyAddr.Text)) {
            $proxyObj = New-Object System.Net.WebProxy("http://" + $txtProxyAddr.Text + ":" + $txtProxyPort.Text)
            $proxyObj.UseDefaultCredentials = $true
        }
    }

    # Override SSL validation (to read certs even if they have errors)
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        $t = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if (-not ($t -match "^http")) { $t = "https://" + $t }

        Log-Write "Inspecting: $t" "White"
        try {
            $req = [System.Net.HttpWebRequest]::Create($t)
            $req.Timeout = 10000
            if ($proxyObj) { $req.Proxy = $proxyObj } else { $req.Proxy = $null }
            try { $null = $req.GetResponse() } catch {}
            
            if ($req.ServicePoint.Certificate) {
                $cert = $req.ServicePoint.Certificate
                $expiry = [DateTime]::Parse($cert.GetExpirationDateString())
                $daysLeft = ($expiry - (Get-Date)).Days
                $issuer = $cert.GetIssuerName()
                
                $msg = "  [VALID] Expires: $($expiry.ToShortDateString()) ($daysLeft days left)"
                if ($daysLeft -lt 0) { Log-Write $msg "Red" }
                elseif ($daysLeft -lt 60) { Log-Write $msg "Yellow" }
                else { Log-Write $msg "Lime" }
                Log-Write "  [ISSUER] $issuer" "Gray"
            } else {
                Log-Write "  [ERROR] No Certificate info returned." "Red"
            }
        } catch {
            Log-Write "  [FAIL] Connection Error: $($_.Exception.Message)" "Red"
        }
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
})

# --- EVENT: SAVE LOGS ---
$btnSave.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log"
    $saveDialog.Title = "Save Diagnostic Report"
    $saveDialog.FileName = "Network_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $rtbLog.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Report saved successfully!", "Export", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error saving file: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})

$btnClear.Add_Click({ $rtbLog.Clear() })

# --- LAUNCH ---
$form.ShowDialog()
