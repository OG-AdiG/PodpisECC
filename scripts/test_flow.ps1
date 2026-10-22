# PodpisECC automated test script (requires server on :8080)
# Messages are ASCII-only so Windows PowerShell consoles display them correctly.
$ErrorActionPreference = "Stop"
$Base = "http://127.0.0.1:8080"
$Tmp = Join-Path $env:TEMP ("podpis_ecc_test_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $Tmp | Out-Null

function Assert-True($cond, $msg) {
    if (-not $cond) { throw "ASSERT FAIL: $msg" }
    Write-Host "OK  $msg" -ForegroundColor Green
}

try {
    Write-Host "=== PodpisECC automated test ===" -ForegroundColor Cyan
    Write-Host "Temp: $Tmp"

    $ui = curl.exe -s -o NUL -w "%{http_code}" "$Base/"
    Assert-True ($ui -eq "200") "UI HTTP 200"

    # 1) Keys with passphrase
    curl.exe -s -X POST "$Base/api/generate-keys" `
        -F "passphrase=sekret123" -F "passphrase_confirm=sekret123" `
        -o (Join-Path $Tmp "keys.json")
    $keys = Get-Content (Join-Path $Tmp "keys.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($keys.encrypted -eq $true) "Private key encrypted with passphrase"
    Assert-True ($keys.private_pem -match "ENCRYPTED") "PEM contains ENCRYPTED"

    $priv = Join-Path $Tmp "private.pem"
    $pub = Join-Path $Tmp "public.pem"
    $doc = Join-Path $Tmp "doc.txt"
    $sig = Join-Path $Tmp "doc.sig"
    $docBad = Join-Path $Tmp "doc_bad.txt"

    Set-Content -Path $priv -Value $keys.private_pem -NoNewline -Encoding utf8
    Set-Content -Path $pub -Value $keys.public_pem -NoNewline -Encoding utf8
    Set-Content -Path $doc -Value "Dokument testowy PodpisECC" -NoNewline -Encoding utf8
    Set-Content -Path $docBad -Value "Dokument testowy PodpisECC ZMIENIONY" -NoNewline -Encoding utf8

    # 2) Hash
    curl.exe -s -X POST "$Base/api/hash" -F "document=@$doc" -o (Join-Path $Tmp "hash.json")
    $hash = Get-Content (Join-Path $Tmp "hash.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($hash.sha256.Length -eq 64) "SHA-256 is 64 hex chars"

    # 3) Sign with passphrase
    curl.exe -s -D (Join-Path $Tmp "sign.hdr") -o $sig `
        -X POST "$Base/api/sign" `
        -F "document=@$doc" -F "private_key=@$priv;filename=private.pem" -F "passphrase=sekret123"
    Assert-True ((Get-Item $sig).Length -gt 0) "Signature file is not empty"
    $hdr = Get-Content (Join-Path $Tmp "sign.hdr") -Raw -Encoding UTF8
    Assert-True ($hdr -match "200 OK") "Sign HTTP 200"

    # 4) Verify OK
    curl.exe -s -X POST "$Base/api/verify" `
        -F "document=@$doc" -F "public_key=@$pub;filename=public.pem" -F "signature=@$sig;filename=doc.sig" `
        -o (Join-Path $Tmp "ver_ok.json")
    $verOk = Get-Content (Join-Path $Tmp "ver_ok.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($verOk.valid -eq $true) "Verify positive (valid signature)"

    # 5) Verify FAIL (modified document)
    curl.exe -s -X POST "$Base/api/verify" `
        -F "document=@$docBad" -F "public_key=@$pub;filename=public.pem" -F "signature=@$sig;filename=doc.sig" `
        -o (Join-Path $Tmp "ver_bad.json")
    $verBad = Get-Content (Join-Path $Tmp "ver_bad.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($verBad.valid -eq $false) "Verify negative after document change"

    # 6) Wrong passphrase on sign
    $badSign = curl.exe -s -o (Join-Path $Tmp "sign_bad.json") -w "%{http_code}" `
        -X POST "$Base/api/sign" `
        -F "document=@$doc" -F "private_key=@$priv;filename=private.pem" -F "passphrase=zlehaslo"
    Assert-True ($badSign -eq "400") "Wrong passphrase => HTTP 400"

    # 7) Benchmark (1 round - faster)
    curl.exe -s -X POST "$Base/api/benchmark" -F "rounds=1" -o (Join-Path $Tmp "bench.json")
    $bench = Get-Content (Join-Path $Tmp "bench.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($null -ne $bench.ecc.keygen_ms) "Benchmark ECC keygen"
    Assert-True ($null -ne $bench.rsa3072.keygen_ms) "Benchmark RSA keygen"

    Write-Host "`nAll tests passed." -ForegroundColor Cyan
    exit 0
}
catch {
    Write-Host "`nFAIL: $_" -ForegroundColor Red
    exit 1
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
