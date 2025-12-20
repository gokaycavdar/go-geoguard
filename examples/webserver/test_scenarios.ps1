# GeoGuard Test Scenarios - PowerShell Script
# Her senaryoyu ayrı ayrı çalıştırabilirsiniz

$baseUrl = "http://localhost:8080/api/v1/login"
$headers = @{
    "Content-Type" = "application/json"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    "Accept-Language" = "tr-TR"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GeoGuard Test Senaryoları" -ForegroundColor Cyan
Write-Host "Önce sunucuyu başlatın: go run ." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# TEST 1: Normal Türk Kullanıcı (Istanbul'dan)
Write-Host "TEST 1: Normal Türk Kullanıcı (Istanbul)" -ForegroundColor Green
$body1 = @{
    userID = "user_normal"
    IPOverride = "88.255.216.1"  # Türk Telekom IP
    latitude = 41.0082
    longitude = 28.9784
    clientTimezone = "Europe/Istanbul"
} | ConvertTo-Json

try {
    $response1 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body1 -Headers $headers
    Write-Host "  Sonuç: $($response1.result.decision)" -ForegroundColor $(if($response1.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response1.result.total_score)"
    Write-Host "  Kurallar: $($response1.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 2: Open Proxy / Tor Exit Node
Write-Host "TEST 2: Open Proxy / Tor Exit Node" -ForegroundColor Red
$body2 = @{
    userID = "user_tor"
    IPOverride = "185.220.101.35"  # Bilinen Tor exit node
    latitude = 52.3676
    longitude = 4.9041
    clientTimezone = "Europe/Amsterdam"
} | ConvertTo-Json

try {
    $response2 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body2 -Headers $headers
    Write-Host "  Sonuç: $($response2.result.decision)" -ForegroundColor $(if($response2.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response2.result.total_score)"
    Write-Host "  Kurallar: $($response2.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 3: AWS Datacenter IP
Write-Host "TEST 3: AWS Datacenter IP" -ForegroundColor Yellow
$body3 = @{
    userID = "user_aws"
    IPOverride = "52.94.76.1"  # AWS IP
    latitude = 47.6062
    longitude = -122.3321
    clientTimezone = "America/Los_Angeles"
} | ConvertTo-Json

try {
    $response3 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body3 -Headers $headers
    Write-Host "  Sonuç: $($response3.result.decision)" -ForegroundColor $(if($response3.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response3.result.total_score)"
    Write-Host "  Kurallar: $($response3.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 4: Timezone Mismatch (VPN İndikatörü)
Write-Host "TEST 4: Timezone Mismatch (VPN İndikatörü)" -ForegroundColor Yellow
$body4 = @{
    userID = "user_vpn_tz"
    IPOverride = "88.255.216.1"  # Türkiye IP
    latitude = 41.0082
    longitude = 28.9784
    clientTimezone = "America/New_York"  # Ama timezone New York!
} | ConvertTo-Json

try {
    $response4 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body4 -Headers $headers
    Write-Host "  Sonuç: $($response4.result.decision)" -ForegroundColor $(if($response4.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response4.result.total_score)"
    Write-Host "  Kurallar: $($response4.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 5: Geofencing Violation (Yasaklı Bölge)
Write-Host "TEST 5: Geofencing - Yasaklı Bölge (Kuzey Kore)" -ForegroundColor Red
$body5 = @{
    userID = "user_nk"
    IPOverride = "175.45.176.1"  # Kuzey Kore IP aralığı
    latitude = 39.0392
    longitude = 125.7625
    clientTimezone = "Asia/Pyongyang"
} | ConvertTo-Json

try {
    $response5 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body5 -Headers $headers
    Write-Host "  Sonuç: $($response5.result.decision)" -ForegroundColor $(if($response5.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response5.result.total_score)"
    Write-Host "  Kurallar: $($response5.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

# TEST 6: IP-GPS Mismatch
Write-Host "TEST 6: IP-GPS Mismatch (Sahte GPS)" -ForegroundColor Yellow
$body6 = @{
    userID = "user_fakegps"
    IPOverride = "88.255.216.1"  # Türkiye IP
    latitude = 35.6762           # Ama GPS Tokyo gösteriyor!
    longitude = 139.6503
    clientTimezone = "Europe/Istanbul"
} | ConvertTo-Json

try {
    $response6 = Invoke-RestMethod -Uri $baseUrl -Method POST -Body $body6 -Headers $headers
    Write-Host "  Sonuç: $($response6.result.decision)" -ForegroundColor $(if($response6.result.decision -eq "ALLOWED") {"Green"} else {"Red"})
    Write-Host "  Risk Skoru: $($response6.result.total_score)"
    Write-Host "  Kurallar: $($response6.result.triggered_rules -join ', ')"
} catch {
    Write-Host "  Hata: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test tamamlandı!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
