# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# The domain to send data to
$TargetDomain = "vpnserver.com"

# Function to resolve the domain to an IP address
function Resolve-Domain {
    param (
        [string]$Domain
    )
    try {
        $Addresses = [System.Net.Dns]::GetHostAddresses($Domain)
        if ($Addresses.Count -eq 0) {
            Write-Host "Failed to resolve domain: $Domain"
            return $null
        }
        return $Addresses[0] # Return the first resolved IP address
    } catch {
        Write-Host "Error resolving domain: $($_.Exception.Message)"
        return $null
    }
}

# Resolve the domain
$TargetIp = Resolve-Domain -Domain $TargetDomain
if (-not $TargetIp) {
    exit
}

# Create a UDP client
$UdpClient = New-Object System.Net.Sockets.UdpClient

try {
    while ($true) {
        # Generate a random port between 1000 and 2000
        $Port = Get-Random -Minimum 1000 -Maximum 2000

        # Create the data (2 bytes representing the port number)
        $byteArray = New-Object Byte[] 2
        $byteArray[0]=[math]::Floor($Port / 256)
        $byteArray[1]=$Port % 256

        # Create the endpoint
        $EndPoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($TargetIp.ToString()), $Port) 

        # Send the data
        $UdpClient.Send($byteArray, $byteArray.Length, $EndPoint) | Out-Null

        Start-Sleep -Seconds 30
    }
} catch {
    Write-Host "An error occurred: $($_.Exception.Message)"
} finally {
    # Clean up the UDP client
    $UdpClient.Dispose()
}
