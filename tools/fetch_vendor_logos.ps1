param(
  [string]$CatalogUrl = "http://192.168.11.90:8110/api/signatures/technologies",
  [string]$OutputDirectory = "frontend/assets/vendor-logos",
  [string]$SimpleIconsVersion = "latest"
)

$ErrorActionPreference = "Stop"
$aliases = @{
  "asp.net" = "dotnet"
  "exchange-owa" = "microsoftoutlook"
  "http-server" = "apache"
  "jboss-wildfly" = "redhat"
  "node-js" = "nodedotjs"
  "red-hat" = "redhat"
  "sharepoint" = "microsoftsharepoint"
  "vba" = "visualbasic"
  "vmware-vcenter" = "vmware"
  "vrealize-operations-manager" = "vmware"
  "aria-operations-for-logs" = "vmware"
  "aria-operations-for-networks" = "vmware"
  "cloud-foundation" = "vmware"
  "sd-wan-orchestrator" = "vmware"
  "workspace-one-access" = "vmware"
}

function ConvertTo-Slug([string]$Value) {
  $slug = ($Value.ToLowerInvariant() -replace "&", " and " -replace "[/.]", "-" -replace "[^a-z0-9]+", "-").Trim("-")
  if ($aliases.ContainsKey($slug)) { return $aliases[$slug] }
  return $slug
}

function Get-Icon([string]$Slug, [string]$Destination) {
  if (-not $Slug) { return $false }
  $uri = "https://cdn.jsdelivr.net/npm/simple-icons@$SimpleIconsVersion/icons/$Slug.svg"
  try {
    $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 30
    if ($response.StatusCode -ne 200 -or [string]::IsNullOrWhiteSpace($response.Content)) { return $false }
    $svg = $response.Content
    if ($svg -notmatch "<svg\s+[^>]*width=") {
      $svg = $svg -replace "<svg\s+", '<svg width="24" height="24" preserveAspectRatio="xMidYMid meet" '
    }
    [IO.File]::WriteAllText($Destination, $svg, [Text.UTF8Encoding]::new($false))
    return $true
  } catch {
    return $false
  }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$catalog = Invoke-RestMethod -Uri $CatalogUrl -TimeoutSec 30
$assets = @{}
foreach ($group in ($catalog.groups | Where-Object { $_.label })) {
  $vendorSlug = ConvertTo-Slug ([string]$group.label)
  $vendorPath = Join-Path $OutputDirectory "$vendorSlug.svg"
  if (-not (Test-Path $vendorPath)) {
    [void](Get-Icon $vendorSlug $vendorPath)
  }
  if (Test-Path $vendorPath) { $assets[[string]$group.label] = $vendorSlug }
  foreach ($child in ($group.children | Where-Object { $_.label })) {
    $productSlug = ConvertTo-Slug ([string]$child.label)
    $productPath = Join-Path $OutputDirectory "$productSlug.svg"
    if (-not (Test-Path $productPath)) {
      [void](Get-Icon $productSlug $productPath)
    }
    if (Test-Path $productPath) { $assets[[string]$child.label] = $productSlug }
  }
}

$manifest = [ordered]@{
  source = "Simple Icons"
  source_url = "https://github.com/simple-icons/simple-icons"
  cdn_template = "https://cdn.jsdelivr.net/npm/simple-icons@$SimpleIconsVersion/icons/{slug}.svg"
  license = "CC0-1.0"
  fetched_at = (Get-Date).ToUniversalTime().ToString("o")
  assets = $assets
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory "manifest.json")
Write-Output "Fetched $($assets.Count) logo assets into $OutputDirectory"
