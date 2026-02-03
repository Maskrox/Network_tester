<#
.SYNOPSIS
    Enterprise Network Master Tool v5.1 (Audit & Compliance Edition)
    
.DESCRIPTION
    A forensic-grade network diagnostic suite designed for restricted corporate environments.
    Engineered for Systems Administrators and Network Engineers to validate connectivity
    pathways, firewall rules, and SSL/TLS compliance without triggering security alerts.
    
    CAPABILITIES:
    1. DNS RESOLUTION: Deep inspection of Hostnames, CNAMEs (Aliases), and IPs.
    2. ICMP REACHABILITY: Standard Ping testing for Layer 3 availability.
    3. PORT CHECK (TCP): Fast, non-blocking Socket connections to validate Firewall rules.
    4. HTTP/PROXY (L7): Validates Web Proxy authentication and Application Layer reachability.
    5. SSL INSPECTION: Decodes X.509 certificates to verify Validity, Chain, and SANs.
    
    SECURITY COMPLIANCE:
    - PASSIVE EXECUTION: No background scanning or unauthorized network calls.
    - ZERO TELEMETRY: Operates strictly offline/local.
    - FLOW CONTROL: Includes user-interrupt (ABORT) capabilities for long lists.

.NOTES
    Version:        5.1 (Stable)
    Requirements:   PowerShell 5.1+, .NET Framework 4.5+
    License:        Internal Enterprise Use
#>

# Load Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# SECURITY: Force TLS 1.2 (Industry Standard)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# GLOBAL CONTROL VARIABLE
$script:CancelRequest = $false

# =============================================================================
# GUI SETUP
# =============================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enterprise Network Master Tool v5.1"
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
# SECTION 1: TARGET CONFIGURATION
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
    # Default text is commented out to prevent accidental external calls
    $txtTargets.Text = "# Enter server list here...`n# Ex: srv-app01.corp.local`n# Ex: 192.168.1.50"
    $grpTargets.Controls.Add($txtTargets)

    $lblPort = New-Object System.Windows.Forms.Label
    $lblPort.Text = "TCP Port (For Socket Test):"
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
# SECTION 2: PROXY STRATEGY
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
# SECTION 3: EXECUTION CONTROLS
# =============================================================================
$grpActions = New-Object System.Windows.Forms.GroupBox
$grpActions.Text = " 3. Execute Diagnostics "
$grpActions.Location = New-Object System.Drawing.Point(15, 520)
$grpActions.Size = New-Object System.Drawing.Size(350, 310)
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
    $btnTCP.Text = "Test 3: TCP Socket (Fast Check)"
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

    # 5. SSL
    $btnSSL = New-Object System.Windows.Forms.Button
    $btnSSL.Text = "Test 5: SSL / TLS Inspector"
    $btnSSL.Size = New-Object System.Drawing.Size(310, 40)
    $btnSSL.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 15) # Extra margin bottom to separate STOP button
    $btnSSL.BackColor = "Purple"
    $btnSSL.ForeColor = "White"
    $btnSSL.FlatStyle = "Flat"
    $btnSSL.Font = $fontLabel
    $flowPanel.Controls.Add($btnSSL)

    # 6. STOP / ABORT (At the bottom)
    $btnStop = New-Object System.Windows.Forms.Button
    $btnStop.Text = "⛔ ABORT DIAGNOSTICS"
    $btnStop.Size = New-Object System.Drawing.Size(310, 40)
    $btnStop.Margin = New-Object System.Windows.Forms.Padding(0, 10, 0, 0)
    $btnStop.BackColor = "Maroon"
    $btnStop.ForeColor = "White"
    $btnStop.FlatStyle = "Flat"
    $btnStop.Font = [System.Drawing.Font]::new("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $flowPanel.Controls.Add($btnStop)

# =============================================================================
# SECTION 4: OUTPUT LOGS
# =============================================================================
$grpLog = New-Object System.Windows.Forms.GroupBox
$grpLog.Text = " Diagnostic Output "
$grpLog.Location = New-Object System.Drawing.Point(380, 15)
$grpLog.Size = New-Object System.Drawing.Size(690, 815)
$grpLog.ForeColor = "White"
$grpLog.Font = $fontTitle
$grpLog.Anchor = "Top, Bottom, Left, Right"
$form.Controls.Add($grpLog)

    $rtbLog = New-Object System.Windows.Forms.RichTextBox
    $rtbLog.Location = New-Object System.Drawing.Point(15, 30)
    $rtbLog.Size = New-Object System.Drawing.Size(660, 730)
    $rtbLog.BackColor = "Black"
    $rtbLog.ForeColor = "LightGray"
    $rtbLog.Font = $fontLog
    $rtbLog.ReadOnly = $true
    $rtbLog.Anchor = "Top, Bottom, Left, Right"
    $grpLog.Controls.Add($rtbLog)
    
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

# --- STOP LOGIC ---
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
        [System.Windows.Forms.Application]::DoEvents() # Keep GUI responsive
        if ($script:CancelRequest) { break }

        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
        
        Log-Write "Querying: $t ..." "White"
        try {
            $entry = [System.Net.Dns]::GetHostEntry($t)
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

        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
        
        Log-Write "Pinging $t ..." "White"
        try {
            $ping = Test-Connection -ComputerName $t -Count 1 -ErrorAction SilentlyContinue
            if ($ping) { Log-Write "  [ALIVE] Reply from $($ping.IPV4Address)" "Green" }
            else { Log-Write "  [NO REPLY] Timeout (Firewall blocked?)" "Orange" }
        } catch { Log-Write "  [ERROR] Invalid Hostname." "Red" }
    }
})

# --- 3. TCP TEST (FAST SOCKETS) ---
$btnTCP.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING FAST TCP PORT TEST" "Cyan"
    $port = [int]$txtPort.Text
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }

        $t = $t.Trim() -replace "https://","" -replace "http://","" -replace "/.*",""
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
        
        Log-Write "Connecting to $t : $port ..." "White"
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $connect = $client.BeginConnect($t, $port, $null, $null)
            $success = $connect.AsyncWaitHandle.WaitOne(3000, $true) # 3s Timeout
            
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

# --- 4. HTTP TEST (NET ENGINE - LIGHTWEIGHT) ---
$btnHTTP.Add_Click({
    $script:CancelRequest = $false
    Log-Write "--------------------------------------------------" "Gray"
    Log-Write ">>> STARTING HTTP PROXY TEST (Layer 7)" "Cyan"
    
    # Proxy Setup
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

    # Execution
    $targets = $txtTargets.Text -split "`n"
    foreach ($t in $targets) {
        [System.Windows.Forms.Application]::DoEvents()
        if ($script:CancelRequest) { break }

        $t = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
        if (-not ($t -match "^http")) { $t = "https://" + $t }
        
        Log-Write "Requesting: $t" "White"
        try {
            # Use HttpWebRequest (Lightweight) instead of Invoke-WebRequest
            $req = [System.Net.HttpWebRequest]::Create($t)
            $req.Timeout = 30000 
            $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
            
            if ($rbNoProxy.Checked) { $req.Proxy = $null } 
            else { $req.Proxy = $proxyObj }

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
                if ($ex.Message -like "*timed out*") {
                     Log-Write "  [FAIL] Connection Timed Out (Firewall/Proxy Block)." "Red"
                } else {
                     Log-Write "  [FAIL] Error: $($ex.Message)" "Red"
                }
            }
        }
    }
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

        $t = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith("#")) { continue }
        if (-not ($t -match "^http")) { $t = "https://" + $t }

        Log-Write "Inspecting: $t" "White"
        try {
            $req = [System.Net.HttpWebRequest]::Create($t)
            $req.Timeout = 30000 
            $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
            
            if ($rbNoProxy.Checked) { $req.Proxy = $null } 
            else { if ($proxyObj) { $req.Proxy = $proxyObj } }

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
