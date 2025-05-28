$services = @("authservice", "gateway", "resourceserver", "jokeservice", "quoteservice")

Write-Host
foreach ($s in $services) {
    Remove-Item "$s\target" -Recurse -Force -ErrorAction SilentlyContinue
}

foreach ($s in $services) {
    Write-Host
    Push-Location $s
    ./mvnw clean package -DskipTests
    Pop-Location
}

Write-Host
docker compose build --no-cache

Write-Host
docker compose up -d --force-recreate
