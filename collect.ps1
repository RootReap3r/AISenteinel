# AI Sentinel - Data Collection Script v1.1 (fixed)
# Run as Administrator

param(
    [int]$EventHours = 24,
    [int]$FilesystemDays = 7,
    [string]$OutputFile = "sentinel_data.json"
)

Write-Host "[AI SENTINEL] Starting data collection..." -ForegroundColor Cyan
$data = @{}
$errors = @()

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] WARNING: Not running as Administrator. Security event log, Defender status, firewall, and process paths may be missing or incomplete." -ForegroundColor Red
}

# 1. EVENT LOGS
Write-Host "[*] Collecting Event Logs (last $EventHours hours)..." -ForegroundColor Yellow
$since = (Get-Date).AddHours(-$EventHours)
$criticalEventIDs = @{4624="Successful Logon";4625="Failed Logon";4634="Logoff";4648="Explicit Creds Logon";4672="Special Privileges";4688="New Process";4689="Process Exit";4698="Scheduled Task Created";4699="Scheduled Task Deleted";4702="Scheduled Task Updated";4719="Audit Policy Changed";4720="User Account Created";4722="User Account Enabled";4724="Password Reset";4725="User Account Disabled";4726="User Account Deleted";4728="Added to Global Group";4732="Added to Local Group";4738="User Account Changed";4756="Added to Universal Group";4768="Kerberos TGT";4769="Kerberos SvcTicket";4771="Kerberos Pre-Auth Fail";4776="Credential Validation";1102="Audit Log Cleared";4616="System Time Changed";4103="PS Module Log";4104="PS Script Block";7036="Service State Change";7045="New Service Installed";5156="Network Connection Allowed"}

$eventLogs = @()
$userPropIdx = @{1102=1;4698=1;4699=1;4702=1;4688=1;4689=1;4719=1;4720=4;4722=2;4724=4;4725=2;4726=2;4728=4;4732=4;4738=4;4756=4;4776=1;7045=4}
foreach ($logName in @("Security","System","Application","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-Windows Defender/Operational")) {
    try {
        $filter = @{LogName=$logName; StartTime=$since}
        if ($logName -notlike "*Defender*") { $filter['Id'] = @($criticalEventIDs.Keys) }
        $rawEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue
        if (-not $rawEvents) { continue }
        foreach ($evt in $rawEvents) {
            $idx = if ($userPropIdx.ContainsKey([int]$evt.Id)) { $userPropIdx[[int]$evt.Id] } else { 5 }
            $userVal = ""; try { $userVal = [string]$evt.Properties[$idx].Value } catch {}
            $msgVal = ""; try { $raw = $evt.Message -replace '\s+',' '; $msgVal = $raw.Substring(0,[Math]::Min(400,$raw.Length)) } catch {}
            $descVal = if ($criticalEventIDs[[int]$evt.Id]) { $criticalEventIDs[[int]$evt.Id] } else { $evt.TaskDisplayName }
            $eventLogs += [PSCustomObject]@{id=$evt.Id;time=$evt.TimeCreated.ToString("o");level=$evt.LevelDisplayName;source=$evt.ProviderName;log=$logName;description=$descVal;message=$msgVal;user=$userVal;computer=$evt.MachineName}
        }
    } catch { $errors += "EventLog[$logName]: $($_.Exception.Message)" }
}
$data.event_logs = $eventLogs
$data.event_summary = @{total=$eventLogs.Count;failed_logons=($eventLogs|Where-Object{$_.id -eq 4625}).Count;new_processes=($eventLogs|Where-Object{$_.id -eq 4688}).Count;new_services=($eventLogs|Where-Object{$_.id -eq 7045}).Count;scheduled_tasks_created=($eventLogs|Where-Object{$_.id -eq 4698}).Count;log_cleared=($eventLogs|Where-Object{$_.id -eq 1102}).Count}
Write-Host "  -> Collected $($eventLogs.Count) events" -ForegroundColor Green

# 2. PROCESSES
Write-Host "[*] Analyzing processes..." -ForegroundColor Yellow
$lolbinList = @("powershell","pwsh","cmd","mshta","wscript","cscript","regsvr32","rundll32","certutil","bitsadmin","msiexec","installutil","regasm","regsvcs","cmstp","msbuild","csc","wmic","schtasks","netsh","esentutl","extrac32","findstr","forfiles","makecab","mavinject","hh","xwizard","wsreset","ntdsutil")
$suspPaths = @("\\temp\\","\\tmp\\","\\appdata\\local\\temp\\","\\appdata\\roaming\\","\\programdata\\","\\users\\public\\","\\downloads\\","\\desktop\\")
$processes = @()
foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
    $pathVal=""; try{$pathVal=[string]$proc.MainModule.FileName}catch{}
    $companyVal=""; try{$companyVal=$proc.MainModule.FileVersionInfo.CompanyName}catch{}
    $isLolbin = $lolbinList -contains $proc.Name.ToLower()
    $suspPath=$false; if($pathVal){foreach($sp in $suspPaths){if($pathVal.ToLower() -like "*$sp*"){$suspPath=$true;break}}}
    $isSigned=$false;$sigStatus="Unknown"
    if($pathVal -and (Test-Path $pathVal)){try{$sig=Get-AuthenticodeSignature $pathVal -EA SilentlyContinue;$isSigned=($sig.Status -eq "Valid");$sigStatus=$sig.Status.ToString()}catch{}}
    $cpuVal=0;try{$cpuVal=[math]::Round($proc.CPU,2)}catch{}
    $memVal=0;try{$memVal=[math]::Round($proc.WorkingSet64/1MB,2)}catch{}
    $processes += [PSCustomObject]@{pid=$proc.Id;name=$proc.Name;path=$pathVal;company=$companyVal;cpu=$cpuVal;memory_mb=$memVal;threads=$proc.Threads.Count;is_lolbin=$isLolbin;suspicious_path=$suspPath;is_signed=$isSigned;signature_status=$sigStatus;has_no_path=($pathVal -eq "")}
}
$data.processes = $processes
$data.process_summary = @{total=$processes.Count;lolbins_running=($processes|Where-Object{$_.is_lolbin}).Count;suspicious_paths=($processes|Where-Object{$_.suspicious_path}).Count;unsigned=($processes|Where-Object{(-not $_.is_signed) -and $_.path -ne ""}).Count;no_path=($processes|Where-Object{$_.has_no_path}).Count;lolbin_list=($processes|Where-Object{$_.is_lolbin}|ForEach-Object{$_.name}|Sort-Object -Unique)}
Write-Host "  -> $($processes.Count) processes ($($data.process_summary.lolbins_running) LOLBins)" -ForegroundColor Green

# 3. NETWORK
Write-Host "[*] Mapping network connections..." -ForegroundColor Yellow
$connections = @()
foreach ($conn in (Get-NetTCPConnection -EA SilentlyContinue)) {
    $procName=""; try{$procName=(Get-Process -Id $conn.OwningProcess -EA SilentlyContinue).Name}catch{}
    $isExt = $conn.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|::|fe80:|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)'
    $suspPort = $conn.RemotePort -in @(4444,5555,1337,31337,6666,7777,8888,9999,12345,54321,6667)
    $connections += [PSCustomObject]@{local_address=$conn.LocalAddress;local_port=$conn.LocalPort;remote_address=$conn.RemoteAddress;remote_port=$conn.RemotePort;state=$conn.State.ToString();pid=$conn.OwningProcess;process=$procName;is_external=$isExt;suspicious_port=$suspPort;is_established=($conn.State -eq "Established")}
}
$data.network = @{tcp_connections=$connections;summary=@{total_tcp=$connections.Count;established=($connections|Where-Object{$_.is_established}).Count;external=($connections|Where-Object{$_.is_external}).Count;suspicious_ports=($connections|Where-Object{$_.suspicious_port}).Count}}
Write-Host "  -> $($connections.Count) TCP connections ($($data.network.summary.external) external)" -ForegroundColor Green

# 4. PERSISTENCE
Write-Host "[*] Auditing persistence..." -ForegroundColor Yellow
$registryItems = @()
foreach ($key in @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")) {
    try {
        $items = Get-ItemProperty -Path $key -EA SilentlyContinue
        if ($items) { foreach ($prop in ($items.PSObject.Properties|Where-Object{$_.Name -notlike "PS*"})) { $valStr=""; try{$valStr=$prop.Value.ToString().Substring(0,[Math]::Min(300,$prop.Value.ToString().Length))}catch{}; $registryItems += [PSCustomObject]@{key=$key;name=$prop.Name;value=$valStr;suspicious=($valStr -match '\\temp\\|\.vbs|\.ps1|\.bat|powershell|wscript|mshta|http')} } }
    } catch { $errors += "Reg[$key]: $($_.Exception.Message)" }
}
$scheduledTasks = @()
foreach ($task in (Get-ScheduledTask -EA SilentlyContinue|Where-Object{$_.State -ne "Disabled"})) {
    $actionStr=""; try{$act=$task.Actions[0];$actionStr="$($act.Execute) $($act.Arguments)";if($actionStr.Length -gt 300){$actionStr=$actionStr.Substring(0,300)}}catch{}
    $scheduledTasks += [PSCustomObject]@{name=$task.TaskName;path=$task.TaskPath;state=$task.State.ToString();action=$actionStr;author=$task.Author;suspicious=($actionStr -match '\\temp\\|\.vbs|\.ps1|powershell.*-enc|wscript|mshta|http');non_microsoft=($task.TaskPath -notlike "\Microsoft\*")}
}
$services = @()
foreach ($svc in (Get-CimInstance Win32_Service -EA SilentlyContinue)) {
    $pathStr=""; try{$pathStr=$svc.PathName.Substring(0,[Math]::Min(300,$svc.PathName.Length))}catch{}
    $services += [PSCustomObject]@{name=$svc.Name;display_name=$svc.DisplayName;state=$svc.State;start_mode=$svc.StartMode;path=$pathStr;account=$svc.StartName;suspicious=($pathStr -match '\\temp\\|\\appdata\\|\\programdata\\|\.vbs|\.ps1|\.bat')}
}
$startupItems = @()
foreach ($folder in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")) {
    if (Test-Path $folder) { foreach ($item in (Get-ChildItem $folder -EA SilentlyContinue)) { $startupItems += [PSCustomObject]@{name=$item.Name;path=$item.FullName;modified=$item.LastWriteTime.ToString("o")} } }
}
$data.persistence = @{registry_run_keys=$registryItems;scheduled_tasks=$scheduledTasks;services=$services;startup_items=$startupItems;summary=@{registry_items=$registryItems.Count;suspicious_registry=($registryItems|Where-Object{$_.suspicious}).Count;scheduled_tasks=$scheduledTasks.Count;suspicious_tasks=($scheduledTasks|Where-Object{$_.suspicious}).Count;non_microsoft_tasks=($scheduledTasks|Where-Object{$_.non_microsoft}).Count;services=$services.Count;suspicious_services=($services|Where-Object{$_.suspicious}).Count;startup_items=$startupItems.Count}}
Write-Host "  -> $($scheduledTasks.Count) tasks, $($registryItems.Count) run keys, $($services.Count) services" -ForegroundColor Green

# 5. FILESYSTEM
Write-Host "[*] Scanning filesystem..." -ForegroundColor Yellow
$recentFiles = @()
$cutoff = (Get-Date).AddDays(-$FilesystemDays)
$exts = @(".exe",".dll",".bat",".cmd",".vbs",".ps1",".js",".hta",".scr",".com",".msi")
foreach ($loc in @($env:TEMP,"$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:ProgramData","C:\Windows\Temp")) {
    if (Test-Path $loc) {
        try {
            foreach ($file in (Get-ChildItem $loc -Recurse -EA SilentlyContinue -Force|Where-Object{(-not $_.PSIsContainer) -and ($_.LastWriteTime -ge $cutoff) -and ($exts -contains $_.Extension.ToLower())}|Select-Object -First 25)) {
                $isSigned=$false;$sigStatus="Unknown"; try{$sig=Get-AuthenticodeSignature $file.FullName -EA SilentlyContinue;$isSigned=($sig.Status -eq "Valid");$sigStatus=$sig.Status.ToString()}catch{}
                $hash=""; try{$hash=(Get-FileHash $file.FullName -Algorithm SHA256 -EA SilentlyContinue).Hash}catch{}
                $recentFiles += [PSCustomObject]@{path=$file.FullName;name=$file.Name;extension=$file.Extension;size=$file.Length;modified=$file.LastWriteTime.ToString("o");is_signed=$isSigned;signature_status=$sigStatus;sha256=$hash}
            }
        } catch {}
    }
}
$data.filesystem = @{recent_suspicious_files=$recentFiles;summary=@{total_found=$recentFiles.Count;unsigned=($recentFiles|Where-Object{-not $_.is_signed}).Count;executables=($recentFiles|Where-Object{$_.extension -eq ".exe"}).Count;scripts=($recentFiles|Where-Object{@(".ps1",".vbs",".bat",".cmd",".js",".hta") -contains $_.extension}).Count}}
Write-Host "  -> $($recentFiles.Count) recent files in high-risk paths" -ForegroundColor Green

# 6. USERS
Write-Host "[*] Auditing users..." -ForegroundColor Yellow
$localUsers = @()
foreach ($u in (Get-LocalUser -EA SilentlyContinue)) {
    $lastLogon=""; try{$lastLogon=$u.LastLogon.ToString("o")}catch{}
    $pwdSet=""; try{$pwdSet=$u.PasswordLastSet.ToString("o")}catch{}
    $localUsers += [PSCustomObject]@{name=$u.Name;enabled=$u.Enabled;last_logon=$lastLogon;password_last_set=$pwdSet;password_required=$u.PasswordRequired;description=$u.Description}
}
$localAdmins = @()
try { foreach ($m in (Get-LocalGroupMember -Group "Administrators" -EA SilentlyContinue)) { $localAdmins += [PSCustomObject]@{name=$m.Name;object_class=$m.ObjectClass;principal_source=$m.PrincipalSource.ToString()} } } catch {}
$data.users = @{local_users=$localUsers;local_admins=$localAdmins;logged_on=@();summary=@{total_local=$localUsers.Count;enabled=($localUsers|Where-Object{$_.enabled}).Count;admins=$localAdmins.Count;no_password_required=($localUsers|Where-Object{-not $_.password_required}).Count}}
Write-Host "  -> $($localUsers.Count) users, $($localAdmins.Count) admins" -ForegroundColor Green

# 7. SYSTEM INFO
Write-Host "[*] Collecting system info..." -ForegroundColor Yellow
$os=Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
$cs=Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
$bios=Get-CimInstance Win32_BIOS -EA SilentlyContinue
$defStatus=@{enabled="Unknown"}
try{$def=Get-MpComputerStatus -EA SilentlyContinue;if($def){$ls="";try{$ls=$def.LastFullScanTime.ToString("o")}catch{};$defStatus=@{enabled=$def.AntivirusEnabled;real_time=$def.RealTimeProtectionEnabled;signature_age_days=$def.AntivirusSignatureAge;last_scan=$ls;am_running=$def.AMServiceEnabled}}}catch{}
$fw=@();try{foreach($fp in (Get-NetFirewallProfile -EA SilentlyContinue)){$fw+=@{profile=$fp.Name;enabled=$fp.Enabled}}}catch{}
$lastBoot="";try{$lastBoot=$os.LastBootUpTime.ToString("o")}catch{}
$totalRam=0;try{$totalRam=[math]::Round($cs.TotalPhysicalMemory/1GB,2)}catch{}
$data.system=@{hostname=$env:COMPUTERNAME;username=$env:USERNAME;domain=$env:USERDOMAIN;os_name=$os.Caption;os_version=$os.Version;os_build=$os.BuildNumber;architecture=$os.OSArchitecture;last_boot=$lastBoot;total_memory_gb=$totalRam;manufacturer=$cs.Manufacturer;model=$cs.Model;bios_version=$bios.SMBIOSBIOSVersion;defender=$defStatus;firewall=$fw;collection_time=(Get-Date).ToString("o");collection_hours=$EventHours}
Write-Host "  -> $($data.system.os_name) on $($data.system.hostname)" -ForegroundColor Green

# 8. DNS CACHE
Write-Host "[*] Capturing DNS cache..." -ForegroundColor Yellow
$dnsEntries=@()
try{foreach($d in (Get-DnsClientCache -EA SilentlyContinue)){$dnsEntries+=[PSCustomObject]@{name=$d.Entry;type=$d.Type.ToString();data=$d.Data;ttl=$d.TimeToLive;status=$d.Status.ToString()}}}catch{}
$data.dns_cache=@{entries=$dnsEntries;summary=@{total=$dnsEntries.Count;unique_domains=($dnsEntries|ForEach-Object{$_.name}|Sort-Object -Unique).Count}}
Write-Host "  -> $($dnsEntries.Count) DNS entries" -ForegroundColor Green

# WRITE OUTPUT
$data.collection_errors=$errors
$data.collection_meta=@{version="1.1";timestamp=(Get-Date).ToString("o");elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
$json=$data|ConvertTo-Json -Depth 10 -Compress
$outDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
[System.IO.File]::WriteAllText((Join-Path $outDir $OutputFile),$json,[System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "[AI SENTINEL] Done! Output: $OutputFile" -ForegroundColor Green
Write-Host "[AI SENTINEL] Errors: $($errors.Count)" -ForegroundColor $(if($errors.Count -gt 0){"Yellow"}else{"Green"})
Write-Host "[AI SENTINEL] Open sentinel_dashboard.html and load the JSON file." -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
