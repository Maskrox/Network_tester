<#
.SYNOPSIS
    Enterprise Network Master Tool v5.6
    
.DESCRIPTION
    A forensic-grade network diagnostic suite designed for restricted corporate environments.
    
    CHANGELOG v5.6:
    - GUI CLEANUP
    
    CAPABILITIES:
    1. DNS RESOLUTION: Deep inspection of Hostnames, CNAMEs (Aliases), and IPs.
    2. ICMP REACHABILITY: Standard Ping testing for Layer 3 availability.
    3. PORT CHECK (TCP): Fast, non-blocking Socket connections (Smart Parsing).
    4. HTTP/PROXY (L7): Validates Web Proxy & App Layer (SSL Bypass for Internal Trust).
    5. SSL INSPECTION: Decodes X.509 certificates to verify Validity, Chain, and SANs.

.NOTES
    Version:        5.6 (Stable)
    Requirements:   PowerShell 5.1+, .NET Framework 4.5+
    License:        Internal Enterprise Use
#>

# Load Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# SECURITY: Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# GLOBAL CONTROL VARIABLE
$script:CancelRequest = $false

# =============================================================================
# GUI SETUP
# =============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enterprise Network Master Tool v5.6"
$form.Size = New-Object System.Drawing.Size(1100, 850)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48) 
$form.ForeColor = "WhiteSmoke"
$form.FormBorderStyle = "Sizable"
$form.MaximizeBox = $true
$form.AutoScroll = $true
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

# --- TYPOGRAPHY ---
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontLabel = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$fontInput = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)
$fontLog   = New-Object System.Drawing.Font("Consolas", 10, [System.Drawing.FontStyle]::Regular)

# =============================================================================
# SECTION 1: TARGET CONFIGURATION
# =============================================================================
$grpTargets = New-Object System.Windows.Forms.GroupBox
$grpTargets.Text = " 1. Target Configuration "
$grpTargets.Location = New-Object System.Drawing.Point(15, 15)
$grpTargets.Size = New-Object System.Drawing.Size(360, 260)
$grpTargets.ForeColor = "Cyan"
$grpTargets.Font = $fontTitle
$grpTargets.Anchor = "Top, Left"
$form.Controls.Add($grpTargets)

    $lblTargets = New-Object System.Windows.Forms.Label
    $lblTargets.Text = "Hostname list (Supports host:port format):"
    $lblTargets.Location = New-Object System.Drawing.Point(20, 30)
    $lblTargets.AutoSize = $true
    $lblTargets.ForeColor = "White"
    $lblTargets.Font = $fontLabel
    $grpTargets.Controls.Add($lblTargets)

    $txtTargets = New-Object System.Windows.Forms.TextBox
    $txtTargets.Multiline = $true
    $txtTargets.ScrollBars = "Vertical"
    $txtTargets.Location = New-Object System.Drawing.Point(20, 55)
    $txtTargets.Size = New-Object System.Drawing.Size(320, 140)
    $txtTargets.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtTargets.ForeColor = "White"
    $txtTargets.Font = $fontInput
    $txtTargets.BorderStyle = "FixedSingle"
    $txtTargets.Text = "# Enter server list here...`n# Ex: srv-app01.corp.local`n# Ex: srv-db01:1433`n# Ex: 192.168.1.50"
    $grpTargets.Controls.Add($txtTargets)

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "Default TCP Port:"  # CLEANED UP TEXT
    $lblPort.Location = New-Object System.Drawing.Point(20, 215)
    $lblPort.AutoSize = $true
    $lblPort.Font = $fontLabel
    $grpTargets.Controls.Add($lblPort)

    $txtPort = New-Object System.Windows.Forms.TextBox
    $txtPort.Location = New-Object System.Drawing.Point(240, 212)
    $txtPort.Size = New-Object System.Drawing.Size(100, 26)
    $txtPort.Text = "443"
    $txtPort.Font = $fontInput
    $txtPort.TextAlign = "Center"
    $txtPort.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtPort.ForeColor = "White"
    $grpTargets.Controls.Add($txtPort)

# =============================================================================
# SECTION 2: PROXY STRATEGY
# =============================================================================
$grpProxy = New-Object System.Windows.Forms.GroupBox
$grpProxy.Text = " 2. Proxy Strategy "
$grpProxy.Location = New-Object System.Drawing.Point(15, 290)
$grpProxy.Size = New-Object System.Drawing.Size(360, 220)
$grpProxy.ForeColor = "Yellow"
$grpProxy.Font = $fontTitle
$grpProxy.Anchor = "Top, Left"
$form.Controls.Add($grpProxy)

    $rbPac = New-Object System.Windows.Forms.RadioButton
    $rbPac.Text = "System / PAC Script (Auto-Detect)"
    $rbPac.Location = New-Object System.Drawing.Point(20, 35)
    $rbPac.Size = New-Object System.Drawing.Size(320, 25)
    $rbPac.ForeColor = "White"
    $rbPac.Font = $fontLabel
    $rbPac.Checked = $false
    $grpProxy.Controls.Add($rbPac)

    $rbManual = New-Object System.Windows.Forms.RadioButton
    $rbManual.Text = "Manual Configuration:"
    $rbManual.Location = New-Object System.Drawing.Point(20, 70)
    $rbManual.Size = New-Object System.Drawing.Size(320, 25)
    $rbManual.ForeColor = "White"
    $rbManual.Font = $fontLabel
    $grpProxy.Controls.Add($rbManual)

    $txtProxyAddr = New-Object System.Windows.Forms.TextBox
    $txtProxyAddr.Location = New-Object System.Drawing.Point(40, 100)
    $txtProxyAddr.Size = New-Object System.Drawing.Size(210, 26)
    $txtProxyAddr.Text = ""
    $txtProxyAddr.Font = $fontInput
    $txtProxyAddr.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtProxyAddr.ForeColor = "White"
    $grpProxy.Controls.Add($txtProxyAddr)

    $txtProxyPort = New-Object System.Windows.Forms.TextBox
    $txtProxyPort.Location = New-Object System.Drawing.Point(260, 100)
    $txtProxyPort.Size = New-Object System.Drawing.Size(80, 26)
    $txtProxyPort.Text = "8080"
    $txtProxyPort.Font = $fontInput
    $txtProxyPort.TextAlign = "Center"
    $txtProxyPort.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $txtProxyPort.ForeColor = "White"
    $grpProxy.Controls.Add($txtProxyPort)

    $rbNoProxy = New-Object System.Windows.Forms.RadioButton
    $rbNoProxy.Text = "No Proxy (Direct Access)"
    $rbNoProxy.Location = New-Object System.Drawing.Point(20, 145)
    $rbNoProxy.Size = New-Object System.Drawing.Size(320, 25)
    $rbNoProxy.ForeColor = "Silver"
    $rbNoProxy.Font = $fontLabel
    $rbNoProxy.Checked = $true
    $grpProxy.Controls.Add($rbNoProxy)

# =============================================================================
# SECTION 3: EXECUTION CONTROLS (FIXED LAYOUT)
# =============================================================================
$grpActions = New-Object System.Windows.Forms.GroupBox
$grpActions.Text = " 3. Execute Diagnostics "
$grpActions.Location = New-Object System.Drawing.Point(15, 520)
$grpActions.Size = New-Object System.Drawing.Size(360, 310)
$grpActions.ForeColor = "LightGreen"
$grpActions.Font = $fontTitle
$grpActions.Anchor = "Top, Left"
$form.Controls.Add($grpActions)

    # 1. STOP Button Panel (Fixed Bottom)
    $pnlFooter = New-Object System.Windows.Forms.Panel
    $pnlFooter.Dock = "Bottom"
    $pnlFooter.Height = 60 
    $pnlFooter.Padding = New-Object System.Windows.Forms.Padding(10)
    $grpActions.Controls.Add($pnlFooter)

    # 2. Scroll Panel (Fills remaining space)
    $flowPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $flowPanel.Dock = "Fill"
    $flowPanel.FlowDirection = "TopDown"
    $flowPanel.WrapContents = $false
    $flowPanel.AutoScroll = $true 
    $flowPanel.Padding = New-Object System.Windows.Forms.Padding(15, 20, 15, 10)
    $grpActions.Controls.Add($flowPanel)
    $flowPanel.BringToFront()

    function Set-BtnStyle ($btn, $color) {
        $btn.Size = New-Object System.Drawing.Size(320, 40)
        $btn.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 8)
        $btn.BackColor = $color
        $btn.ForeColor = "White"
        $btn.FlatStyle = "Flat"
        $btn.FlatAppearance.BorderSize = 0
        $btn.Font = $fontLabel
        $btn.Cursor = [System.Windows.Forms.Cursors]::Hand
    }

    $btnDNS = New-Object System.Windows.Forms.Button
    $btnDNS.Text = "Test 1: DNS Lookup (Full Info)"
    Set-BtnStyle $btnDNS "DimGray"
    $flowPanel.Controls.Add($btnDNS)

    $btnPing = New-Object System.Windows.Forms.Button
    $btnPing.Text = "Test 2: ICMP Ping"
    Set-BtnStyle $btnPing "DimGray"
    $flowPanel.Controls.Add($btnPing)

    $btnTCP = New-Object System.Windows.Forms.Button
    $btnTCP.Text = "Test 3: TCP Socket (Fast Check)"
    Set-BtnStyle $btnTCP "DimGray"
    $flowPanel.Controls.Add($btnTCP)

    $btnHTTP = New-Object System.Windows.Forms.Button
    $btnHTTP.Text = "Test 4: HTTP / PROXY (Layer 7)"
    Set-BtnStyle $btnHTTP "SeaGreen"
    $btnHTTP.Font = [System.Drawing.Font]::new("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $flowPanel.Controls.Add($btnHTTP)

    $btnSSL = New-Object System.Windows.Forms.Button
    $btnSSL.Text = "Test 5: SSL / TLS Inspector"
    Set-BtnStyle $btnSSL "Purple"
    $flowPanel.Controls.Add($btnSSL)

    # STOP Button (In Footer)
    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Text = "⛔ ABORT DIAGNOSTICS"
    $btnStop.Dock = "Fill"
    $btnStop.BackColor = "Maroon"
    $btnStop.ForeColor = "White"
    $btnStop.FlatStyle = "Flat"
    $btnStop.FlatAppearance.BorderSize = 0
    $btnStop.Font = [System.Drawing.Font]::new("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $btnStop.Cursor = [System.Windows.Forms.Cursors]::Hand
    $pnlFooter.Controls.Add($btnStop)

# =============================================================================
# SECTION 4: OUTPUT LOGS
# =============================================================================
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = " Diagnostic Output "
$grpLog.Location = New-Object System.Drawing.Point(390, 15)
$grpLog.Size = New-Object System.Drawing.Size(680, 815)
$grpLog.ForeColor = "White"
$grpLog.Font = $fontTitle
$grpLog.Anchor = "Top, Bottom, Left, Right"
$form.Controls.Add($grpLog)

    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Location = New-Object System.Drawing.Point(15, 30)
    $rtbLog.Size = New-Object System.Drawing.Size(650, 725)
    $rtbLog.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $rtbLog.ForeColor = "LightGray"
    $rtbLog.Font = $fontLog
    $rtbLog.ReadOnly = $true
    $rtbLog.ScrollBars = "Vertical"
    $rtbLog.BorderStyle = "None"
    $rtbLog.Anchor = "Top, Bottom, Left, Right"
    $grpLog.Controls.Add($rtbLog)
    
    $btnClear = New-Object System.Windows.Forms.Button
    $btnClear.Text = "Clear Logs"
    $btnClear.Location = New-Object System.Drawing.Point(15, 765)
    $btnClear.Size = New-Object System.Drawing.Size(320, 35)
    $btnClear.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $btnClear.ForeColor = "White"
    $btnClear.FlatStyle = "Flat"
    $btnClear.FlatAppearance.BorderSize = 0
    $btnClear.Font = $fontLabel
    $btnClear.Anchor = "Bottom, Left"
    $grpLog.Controls.Add($btnClear)

    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "💾 Export Report to File"
    $btnSave.Location = New-Object System.Drawing.Point(345, 765)
    $btnSave.Size = New-Object System.Drawing.Size(320, 35)
    $btnSave.BackColor = "DimGray"
    $btnSave.ForeColor = "White"
    $btnSave.FlatStyle = "Flat"
    $btnSave.FlatAppearance.BorderSize = 0
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

function Get-CleanHost ($raw) {
    $step1 = $raw -replace "https://","" -replace "http://","" -replace "/.*",""
    $step2 = $step1 -split ":"
    return $step2[0]
}

function Get-SmartPort ($raw, $defaultPort) {
    $clean = $raw -replace "https://","" -replace "http://","" -replace "/.*",""
    if ($clean -match ":(\d+)") { return $matches[1] }
    return $defaultPort
}

$btnStop.Add_Click({
    $script:CancelRequest = $true
    Log-Write ">>> PROCESS ABORTED BY USER <<<" "Red"
})

# --- 1. DNS TEST ---
$btnDNS.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING FULL DNS LOOKUP" "Cyan"
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }
        if ([string]::IsNullOrWhiteSpace($t) -or $t.Trim().StartsWith("#")) { continue }
        
        $hostOnly = Get-CleanHost $t.Trim()
        Log-Write "Querying: $hostOnly ..." "White"
        try {
            $entry = [System.Net.Dns]::GetHostEntry($hostOnly)
            Log-Write "  [NAME]  $($entry.HostName)" "Lime"
            if ($entry.Aliases) { foreach ($alias in $entry.Aliases) { Log-Write "  [ALIAS] $alias" "Yellow" } }
            foreach ($ip in $entry.AddressList) { Log-Write "  [IP]    $($ip.IPAddressToString)" "Gray" }
        } catch { Log-Write "  [DNS FAIL] Host not found / No records." "Red" }
    }
})

# --- 2. PING TEST ---
$btnPing.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING ICMP PING TEST" "Cyan"
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }
        if ([string]::IsNullOrWhiteSpace($t) -or $t.Trim().StartsWith("#")) { continue }

        $hostOnly = Get-CleanHost $t.Trim()
        Log-Write "Pinging $hostOnly ..." "White"
        try {
            $ping = Test-Connection -ComputerName $hostOnly -Count 1 -ErrorAction SilentlyContinue
            if ($ping) { Log-Write "  [ALIVE] Reply from $($ping.IPV4Address)" "Green" }
            else { Log-Write "  [NO REPLY] Timeout (Firewall blocked?)" "Orange" }
        } catch { Log-Write "  [ERROR] Invalid Hostname." "Red" }
    }
})

# --- 3. TCP TEST ---
$btnTCP.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING FAST TCP PORT TEST" "Cyan"
    $defPort = [int]$txtPort.Text
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }
        if ([string]::IsNullOrWhiteSpace($t) -or $t.Trim().StartsWith("#")) { continue }
        
        $raw = $t.Trim()
        $hostOnly = Get-CleanHost $raw
        $usePort = Get-SmartPort $raw $defPort

        Log-Write "Connecting to $hostOnly : $usePort ..." "White"
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $connect = $client.BeginConnect($hostOnly, $usePort, $null, $null)
            $success = $connect.AsyncWaitHandle.WaitOne(3000, $true)
            
            if ($success) {
                if ($client.Connected) {
                    Log-Write "  [OPEN] Connection Established." "Green"
                    $client.EndConnect($connect)
                } else { Log-Write "  [CLOSED] Connection Refused." "Red" }
            } else { Log-Write "  [TIMEOUT] Dropped (Firewall blocked)." "Red" }
            $client.Close()
        } catch { Log-Write "  [ERROR] Resolve/Network Error." "Red" }
    }
})

# --- 4. HTTP TEST ---
$btnHTTP.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING HTTP PROXY TEST (Layer 7)" "Cyan"
    
    $proxyObj = $null
    try {
        if ($rbPac.Checked) {
            Log-Write "Strategy: SYSTEM / PAC (Auto-Detect)" "Yellow"
            $proxyObj = [System.Net.WebRequest]::GetSystemWebProxy()
            $proxyObj.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        } elseif ($rbManual.Checked) {
            if ([string]::IsNullOrWhiteSpace($txtProxyAddr.Text)) { Log-Write "Error: Proxy Address empty." "Red"; return }
            $p = "http://" + $txtProxyAddr.Text + ":" + $txtProxyPort.Text
            Log-Write "Strategy: MANUAL PROXY ($p)" "Yellow"
            $proxyObj = New-Object System.Net.WebProxy($p)
            $proxyObj.UseDefaultCredentials = $true
        } else {
            Log-Write "Strategy: DIRECT ACCESS" "Magenta"
            $proxyObj = [System.Net.WebRequest]::GetSystemWebProxy()
        }
    } catch { Log-Write "Proxy Config Error: $($_.Exception.Message)" "Red"; return }

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }
        if ([string]::IsNullOrWhiteSpace($t) -or $t.Trim().StartsWith("#")) { continue }

        $url = $t.Trim()
        if (-not ($url -match "^http")) { 
            if ($url -match ":80$") { $url = "http://" + $url }
            else { $url = "https://" + $url }
        }
        
        Log-Write "Requesting: $url" "White"
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Timeout = 30000 
            $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
            if ($rbNoProxy.Checked) { $req.Proxy = $null } else { $req.Proxy = $proxyObj }

            $resp = $req.GetResponse()
            $c = [int]$resp.StatusCode
            Log-Write "  [SUCCESS] $c $($resp.StatusDescription)" "Green"
            $resp.Close()
        } catch {
            $ex = $_.Exception
            if ($ex.Response) {
                $c = [int]$ex.Response.StatusCode
                if ($c -eq 404 -or $c -eq 403) { Log-Write "  [CONNECTED] Reached Server (Code $c)." "Lime" }
                elseif ($c -eq 407) { Log-Write "  [BLOCKED] Proxy Auth Required (407)." "Red" }
                else { Log-Write "  [WARNING] Server Code $c" "Orange" }
            } else { 
                if ($ex.Message -like "*timed out*") { Log-Write "  [FAIL] Connection Timed Out (Firewall/Proxy Block)." "Red" }
                else { Log-Write "  [FAIL] Error: $($ex.Message)" "Red" }
            }
        }
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
})

# --- 5. SSL TEST ---
$btnSSL.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING ADVANCED SSL/TLS INSPECTION" "Cyan"
    
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

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }
        if ([string]::IsNullOrWhiteSpace($t) -or $t.Trim().StartsWith("#")) { continue }

        $url = $t.Trim()
        if (-not ($url -match "^http")) { $url = "https://" + $url }

        Log-Write "Inspecting: $url" "White"
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Timeout = 30000 
            $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            if ($rbNoProxy.Checked) { $req.Proxy = $null } else { if ($proxyObj) { $req.Proxy = $proxyObj } }

            try { $null = $req.GetResponse() } catch {}
            
            if ($req.ServicePoint.Certificate) {
                $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($req.ServicePoint.Certificate)
                $expiry = $cert2.NotAfter
                $daysLeft = ($expiry - (Get-Date)).Days
                $msgDate = "  [VALIDITY] Expires: $($expiry.ToShortDateString()) ($daysLeft days left)"
                if ($daysLeft -lt 0) { Log-Write $msgDate "Red" }
                elseif ($daysLeft -lt 60) { Log-Write $msgDate "Yellow" }
                else { Log-Write $msgDate "Lime" }
                Log-Write "  [THUMB]    $($cert2.Thumbprint)" "Magenta"
                Log-Write "  [ISSUER]   $($cert2.Issuer)" "Gray"
                $sanExt = $cert2.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
                if ($sanExt) { Log-Write "  [SANs]     $($sanExt.Format($true))" "Cyan" }
                else { Log-Write "  [SANs]     None (Single Host)" "Gray" }
            } else { Log-Write "  [ERROR] No Certificate info." "Red" }
        } catch { Log-Write "  [FAIL] Connection Error: $($_.Exception.Message)" "Red" }
        Log-Write "" "Black"
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
})

# --- SAVE LOGS ---
$btnSave.Add_Click({
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
    $saveDialog.Title = "Save Diagnostic Report"
    $saveDialog.FileName = "NetReport_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $rtbLog.Text | Out-File -FilePath $saveDialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Report saved successfully!", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error saving file: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
})

$btnClear.Add_Click({ $rtbLog.Clear() })

# LAUNCH
$form.ShowDialog()


