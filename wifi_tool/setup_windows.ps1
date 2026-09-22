# ============================================================
# WiFi 测试工具 - Windows 计算节点一键配置脚本
# 用法：右键 -> 使用 PowerShell 运行（需管理员权限）
# ============================================================

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] 请以管理员身份运行此脚本！" -ForegroundColor Red
    Write-Host "    右键 -> 以管理员身份运行 PowerShell，然后执行此脚本"
    pause
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WiFi 工具 - Windows 计算节点配置" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ---- 1. 安装 OpenSSH Server ----
Write-Host "[1/5] 检查 OpenSSH Server..." -ForegroundColor Yellow
$sshServer = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
if ($sshServer.State -eq "Installed") {
    Write-Host "      已安装，跳过" -ForegroundColor Green
} else {
    Write-Host "      正在安装 OpenSSH Server..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Write-Host "      安装完成" -ForegroundColor Green
}

# ---- 2. 启动服务 ----
Write-Host "[2/5] 启动 sshd 服务并设为自动..." -ForegroundColor Yellow
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
$svc = Get-Service sshd
Write-Host "      服务状态: $($svc.Status)，启动类型: $($svc.StartType)" -ForegroundColor Green

# ---- 3. 配置默认 Shell 为 PowerShell ----
Write-Host "[3/5] 配置默认 Shell 为 PowerShell..." -ForegroundColor Yellow
$regPath = "HKLM:\SOFTWARE\OpenSSH"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
New-ItemProperty -Path $regPath -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null
Write-Host "      已配置" -ForegroundColor Green

# ---- 4. 防火墙 ----
Write-Host "[4/5] 检查防火墙规则..." -ForegroundColor Yellow
$rule = Get-NetFirewallRule -Name "sshd" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    Write-Host "      防火墙规则已添加（端口 22）" -ForegroundColor Green
} else {
    Write-Host "      防火墙规则已存在" -ForegroundColor Green
}

# ---- 5. 公钥配置提示 ----
Write-Host "[5/5] 配置 SSH 公钥免密..." -ForegroundColor Yellow
$userProfile = $env:USERPROFILE
$sshDir = "$userProfile\.ssh"
$authKeys = "$sshDir\authorized_keys"
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}
Write-Host "      authorized_keys 路径: $authKeys" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  配置完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "接下来需要配置 SSH 免密登录：" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. 在 Kali 上执行（如果还没有密钥）：" -ForegroundColor White
Write-Host "   ssh-keygen -t rsa -b 4096" -ForegroundColor Gray
Write-Host ""
Write-Host "2. 把 Kali 公钥传到 Windows（替换为你的用户名和IP）：" -ForegroundColor White
Write-Host "   scp ~/.ssh/id_rsa.pub <windows-user>@<windows-ip>:C:/Users/<windows-user>/.ssh/authorized_keys" -ForegroundColor Gray
Write-Host ""
Write-Host "3. 测试免密登录（在 Kali 上执行）：" -ForegroundColor White
Write-Host "   ssh <windows-user>@<windows-ip> whoami" -ForegroundColor Gray
Write-Host ""
Write-Host "4. 确认 Hashcat 路径，然后在 Web UI 的「配置」页面填写：" -ForegroundColor White
Write-Host "   - Windows IP: 本机 IP（执行 ipconfig 查看）" -ForegroundColor Gray
Write-Host "   - Windows 用户名: $env:USERNAME" -ForegroundColor Gray
Write-Host "   - Hashcat 路径: 例如 C:\hashcat-6.2.6\hashcat.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "本机 IP 地址：" -ForegroundColor Yellow
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | ForEach-Object {
    Write-Host "   $($_.IPAddress)  ($($_.InterfaceAlias))" -ForegroundColor Green
}
Write-Host ""
pause
