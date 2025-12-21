# GeoGuard Test Scenarios - PowerShell Script
# Her senaryoyu ayri ayri calistirabilirsiniz

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$baseUrl = "http://localhost:8080/api/v1/login"
$headers = @{
    "Content-Type" = "application/json"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    "Accept-Language" = "tr-TR"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GeoGuard Test Senaryolari" -ForegroundColor Cyan
Write-Host "Once sunucuyu baslatin: go run ." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# TEST 1: Normal Turk Kullanici (Istanbul'dan)
Write-Host "TEST 1: Normal Turk Kullanici (Istanbul)" -ForegroundColor Green
$body1 = @{
    user_id = "user_normal"
    ip_override = "88.255.216.1"
    latitude = 41.0082
    longitude = 28.9784
    timezone = "Europe/Istanbul"
} | ConvertTo-Json

try {
    $response1 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body1 -Headers $headers
    $color1 = if($response1.status -eq "ALLOWED") {"Green"} elseif($response1.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response1.status)" -ForegroundColor $color1
    Write-Host "  Risk Score: $($response1.risk_score)"
    if ($response1.violations) {
        $rules = ($response1.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 2: Open Proxy / Tor Exit Node
Write-Host "TEST 2: Open Proxy / Tor Exit Node" -ForegroundColor Red
$body2 = @{
    user_id = "user_tor"
    ip_override = "185.220.101.35"
    latitude = 52.3676
    longitude = 4.9041
    timezone = "Europe/Amsterdam"
} | ConvertTo-Json

try {
    $response2 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body2 -Headers $headers
    $color2 = if($response2.status -eq "ALLOWED") {"Green"} elseif($response2.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response2.status)" -ForegroundColor $color2
    Write-Host "  Risk Score: $($response2.risk_score)"
    if ($response2.violations) {
        $rules = ($response2.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 3: AWS Datacenter IP
Write-Host "TEST 3: AWS Datacenter IP" -ForegroundColor Yellow
$body3 = @{
    user_id = "user_aws"
    ip_override = "52.94.76.1"
    latitude = 47.6062
    longitude = -122.3321
    timezone = "America/Los_Angeles"
} | ConvertTo-Json

try {
    $response3 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body3 -Headers $headers
    $color3 = if($response3.status -eq "ALLOWED") {"Green"} elseif($response3.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response3.status)" -ForegroundColor $color3
    Write-Host "  Risk Score: $($response3.risk_score)"
    if ($response3.violations) {
        $rules = ($response3.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 4: Timezone Mismatch (VPN Indicator)
Write-Host "TEST 4: Timezone Mismatch (VPN Indicator)" -ForegroundColor Yellow
$body4 = @{
    user_id = "user_vpn_tz"
    ip_override = "88.255.216.1"
    latitude = 41.0082
    longitude = 28.9784
    timezone = "America/New_York"
} | ConvertTo-Json

try {
    $response4 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body4 -Headers $headers
    $color4 = if($response4.status -eq "ALLOWED") {"Green"} elseif($response4.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response4.status)" -ForegroundColor $color4
    Write-Host "  Risk Score: $($response4.risk_score)"
    if ($response4.violations) {
        $rules = ($response4.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 5: Geofencing Violation (Remote Region)
Write-Host "TEST 5: Geofencing - Remote Region (Outside Allowed Area)" -ForegroundColor Red
$body5 = @{
    user_id = "user_remote"
    ip_override = "103.76.228.1"  # Vietnam IP (far from Turkey)
    latitude = 0                   # No GPS data - only Geofencing should trigger
    longitude = 0
    timezone = "Asia/Ho_Chi_Minh"
} | ConvertTo-Json

try {
    $response5 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body5 -Headers $headers
    $color5 = if($response5.status -eq "ALLOWED") {"Green"} elseif($response5.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response5.status)" -ForegroundColor $color5
    Write-Host "  Risk Score: $($response5.risk_score)"
    if ($response5.violations) {
        $rules = ($response5.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 6: IP-GPS Mismatch
Write-Host "TEST 6: IP-GPS Mismatch (Fake GPS - VPN Detection)" -ForegroundColor Yellow
$body6 = @{
    user_id = "user_fakegps"
    ip_override = "88.255.216.1"  # Turkey IP
    latitude = 35.6762            # But GPS shows Tokyo!
    longitude = 139.6503
    timezone = "Europe/Istanbul"
} | ConvertTo-Json

try {
    $response6 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body6 -Headers $headers
    $color6 = if($response6.status -eq "ALLOWED") {"Green"} elseif($response6.status -eq "REVIEW") {"Yellow"} else {"Red"}
    Write-Host "  Status: $($response6.status)" -ForegroundColor $color6
    Write-Host "  Risk Score: $($response6.risk_score)"
    if ($response6.violations) {
        $rules = ($response6.violations | ForEach-Object { $_.rule }) -join ', '
        Write-Host "  Triggered Rules: $rules"
    }
} catch {
    Write-Host "  Error: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
