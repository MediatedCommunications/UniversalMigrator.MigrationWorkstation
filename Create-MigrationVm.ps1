# WARNING:  This command must be run in Powershell before running this script:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force


# WARNING:  Windows Auto-Play (the auto opening of attached drives) will
# silently prevent this script from working.  Disable AutoPlay on the VMHost running this script.
#
# AutoPlay can be disabled by running:
# New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun  -value 255 -type Dword
# and then rebooting the VMHost.

#
# This script creates a VM that is ideal for a migration specialist.
#
#
# It has notes regarding how long different sections might take.  These will vary based on your 
# hardware and internet connection, However, they were generated using a desktop computer that
# was considered top-of-the-line in 2018 on a personal wired internet connection and then
# rounded up to the nearest 30 seconds.


### The following variables should be configured per your environment


$Host_Root_Apps = 'C:\VMs' # The folder on your physical computer that the VM's Apps drive (C:\) VHD should be created in.
$Host_Root_Data = 'Z:\VMs' # The folder on your physical computer that the VM's Data drive VHD should be created in.
                            
$VM_Name = 'TEST2024A'           #The name you want the VM to have.
$VM_Password = 'Random13579!'  #The password you want the Admistrator user on the VM to have.

$VM_Name_NetBios = '' #The Windows PC name.  Blank will use the VM Name.  Must be <= 15 Characters Long

$VM_Hardware_Cores = 14               #The number of CPU Cores/threads for the VM.  It cannot exceed the number in you physical machine.
$VM_Hardware_AppsDrive_Size = 250GB   # Apps Drive Size.
$VM_Hardware_DataDrive_Size = 1024GB  # Data Drive Size.
$VM_Hardware_DataDrive_Letter = 'B'   # Data Drive Letter.  Default is 'B' for 'Big'.

#This should be changed to the external network
$VM_Hardware_Switch = 'External Network'

$VM_OS = "Windows 11 Pro"
$VM_OS_ISO = 'Z:\REPOSITORY\en-us_windows_11_business_editions_version_23h2_updated_dec_2023_x64_dvd_d9da936d.iso'
$VM_OS_Key = 'CB2NG-KMV8P-YTJCD-W4XRH-B7V26'

$Install_Workstation_Development = $true
$Install_Workstation_Migration   = $false
$Install_Workstation_Desktop     = $false

### DO NOT MODIFY ANYTHING AFTER THIS LINE
#This function gives us a way to wait for a VM to be PowerShell accessible.
function Wait-VMAccess {
   param (
    [string]$VMName,
    [System.Management.Automation.PSCredential]$Credential
   )
    while($true){
        try {
            Wait-VM -VMName $VMName -For IPAddress
            Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock { } -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Seconds 5
        }
    }
}

if($VM_Name_NetBios -eq ''){
    $VM_Name_NetBios = $VM_Name
}


$VM_Name_NetBios_MaxLength = 15

if($VM_Name_NetBios.Length -gt $VM_Name_NetBios_MaxLength){
    Write-Error "The NetBios name $($VM_Name_NetBios) is too long.  It must be <= $($VM_Name_NetBios_MaxLength) Characters."
    RETURN
}

#-------Load the Convert-WindowsImage command
$ExternalScriptUri = "https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/main/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.psm1"

$ExternalScriptResponse = Invoke-WebRequest -Uri $ExternalScriptURI
$ExternalScriptContent = $ExternalScriptResponse.Content

Invoke-Expression $ExternalScriptContent


#-------Create the VM and Install Windows.
#Duration:  9 Minutes

### Create the VM
Write-Host "Creating the VM..."

$VM_VHD_Root_Apps = "$($Host_Root_Apps)\$($VM_Name)"
$VM_VHD_Root_Data = "$($Host_Root_Data)\$($VM_Name)"

$VM_CheckpointPath = "$($Host_Root_Apps)\$($VM_Name)"
$VM_PagePath = "$($Host_Root_Data)\$($VM_Name)"

mkdir $VM_VHD_Root_Apps -Force
mkdir $VM_VHD_Root_Data -Force


$VM_VHD_Apps = "$($VM_VHD_Root_Apps)\$($VM_Name)-Apps.vhdx"
$VM_VHD_Data = "$($VM_VHD_Root_Data)\$($VM_Name)-Data.vhdx"


$VM = New-VM -Name $VM_Name -Generation 2 -MemoryStartupBytes 4GB -BootDevice VHD -NewVHDPath $VM_VHD_Apps -NewVHDSizeBytes $VM_Hardware_AppsDrive_Size -SwitchName $VM_Hardware_Switch

# Set the Paging Path
Move-VMStorage -VM $VM -SmartPagingFilePath $VM_PagePath

# Set the Checkpoint Path
Set-VM -VM $VM -SnapshotFileLocation $VM_CheckpointPath

# Enable Integration Services
Set-VM -VM $VM -AutomaticCheckpointsEnabled $false

# Enable Integration Services
Enable-VMIntegrationService -VM $VM -Name 'Guest Service Interface'

# Enable TPM
Set-VMKeyProtector -VM $VM -NewLocalKeyProtector
Enable-VMTPM $VM

# Set the Cores
Set-VMProcessor -VM $VM -Count $VM_Hardware_Cores

# Enable Nested Virtualization
Set-VMProcessor -VM $VM -ExposeVirtualizationExtensions $true

# Add a Dvd Drive
Add-VMDvdDrive -VM $VM

# Create the Data Drive
New-VHD -Path $VM_VHD_Data -Dynamic -SizeBytes $VM_Hardware_DataDrive_Size

Add-VMHardDiskDrive -VM $VM -Path $VM_VHD_Data

# Set the VM Boot Order to DVD, AppsDrive, DataDrive, Network
$CurrentBootOrder = (Get-VMFirmware -VM $VM).BootOrder

$NewBootOrder = ($CurrentBootOrder[2], $CurrentBootOrder[0], $CurrentBootOrder[3], $CurrentBootOrder[1] )

Set-VMFirmware -VM $VM -BootOrder $NewBootOrder

# Install Windows
Write-Host "Installing Windows..."

$AutoUnattendContent = @"

<?xml version="1.0" encoding="utf-8"?>
<unattend
	xmlns="urn:schemas-microsoft-com:unattend"
	xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
	<settings pass="offlineServicing" />
	<settings pass="windowsPE">
		<component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<SetupUILanguage>
				<UILanguage>en-US</UILanguage>
			</SetupUILanguage>
			<InputLocale>en-US</InputLocale>
			<SystemLocale>en-US</SystemLocale>
			<UILanguage>en-US</UILanguage>
			<UserLocale>en-US</UserLocale>
		</component>
		<component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<UserData>
				<AcceptEula>true</AcceptEula>
			</UserData>
		</component>
	</settings>
	<settings pass="generalize" />
	<settings pass="specialize">
		<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"
			xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
			xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
			<ComputerName>$($VM_Name)</ComputerName>
		</component>


        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <RunSynchronous>

                <RunSynchronousCommand wcm:action="add">
                    <Description>DisableWindowsConsumerFeatures</Description>
                    <Order>1</Order>
                    <Path>reg add HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>

                <RunSynchronousCommand wcm:action="add">
                    <Description>DisableTelemetry</Description>
                    <Order>2</Order>
                    <Path>reg add HKLM\Software\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry  /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>

            </RunSynchronous>
        </component>


	</settings>
	<settings pass="auditSystem" />
	<settings pass="auditUser" />
	<settings pass="oobeSystem">
		<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<InputLocale>en-US</InputLocale>
			<SystemLocale>en-US</SystemLocale>
			<UILanguage>en-US</UILanguage>
			<UserLocale>en-US</UserLocale>
		</component>



		<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<UserAccounts>
				<AdministratorPassword>
					<Value>$($VM_Password)</Value>
					<PlainText>true</PlainText>
				</AdministratorPassword>
			</UserAccounts>
			<AutoLogon>
				<Password>
					<Value>$($VM_Password)</Value>
					<PlainText>true</PlainText>
				</Password>
				<Username>Administrator</Username>
				<Enabled>true</Enabled>
				<LogonCount>5</LogonCount>
			</AutoLogon>
			<OOBE>
				<VMModeOptimizations>
					<SkipAdministratorProfileRemoval>false</SkipAdministratorProfileRemoval>
				</VMModeOptimizations>
				<HideEULAPage>true</HideEULAPage>
				<HideLocalAccountScreen>true</HideLocalAccountScreen>
				<HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
				<HideOnlineAccountScreens>true</HideOnlineAccountScreens>
				<HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
				<ProtectYourPC>1</ProtectYourPC>
				<UnattendEnableRetailDemo>false</UnattendEnableRetailDemo>
				<NetworkLocation>Work</NetworkLocation>
				<SkipMachineOOBE>true</SkipMachineOOBE>
				<SkipUserOOBE>true</SkipUserOOBE>
			</OOBE>
		</component>
	</settings>
</unattend>

"@

$AutoUnattendFile = New-TemporaryFile

$AutoUnattendContent | Out-File $AutoUnattendFile

Convert-WindowsImage -SourcePath $VM_OS_ISO -DiskLayout UEFI -VhdFormat VHDX -VhdType Dynamic -BcdInVhd VirtualMachine -RemoteDesktopEnable -Edition $VM_OS -VhdPath $VM_VHD_Apps -UnattendPath $AutoUnattendFile -SizeBytes $VM_Hardware_AppsDrive_Size

# Start the VM

$VM_Password_Secure = ConvertTo-SecureString $VM_Password -AsPlainText -Force
$VM_Admin_Login = new-object -typename System.Management.Automation.PSCredential -argumentlist 'Administrator',$VM_Password_Secure

Start-VM $VM

Wait-VMAccess $VM.Name -Credential $VM_Admin_Login

#-------Do some general configuration.
#Duration:  2 Minutes




# Set some general system settings
Write-Host "Applying Optimized Windows Settings..."
Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
    
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

    # Activate Windows
    $VM_OS_Key = $Using:VM_OS_Key

    if($VM_OS_Key){
        $KMS = Get-WMIObject -query "select * from SoftwareLicensingService"
        $KMS.InstallProductKey($VM_OS_Key)
        $KMS.RefreshLicenseStatus()
    }

    # Disable UAC
    Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system' -Name 'EnableLUA' -Value 0 -Force

    # Disable Windows Hello
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions' -Name 'value' -Value 0 -Force

    # Disable OOBE
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Force
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Name 'DisablePrivacyExperience' -Value 1 -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'HideFirstRunExperience' -Value 1 -Force

    # Enable Long Paths
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1 -Force

    # Use Dark Mode
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'SystemUsesLightTheme' -Value 0 -Force
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Value 0 -Force

    # Use a Red Cursor
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Accessibility' -Name 'CursorColor' -Value 255 -Force
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Accessibility' -Name 'CursorSize' -Value 2 -Force
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Accessibility' -Name 'CursorType' -Value 6 -Force

    # Do not auto-adjust volume on calls
    # https://learn.microsoft.com/en-us/answers/questions/879800/how-disabled-auto-adjust-level-sound-in-windows-10
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Multimedia\Audio' -Name 'UserDuckingPreference' -Value 3 -Force

    
    # No wallpaper
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name wallpaper -value ''
    rundll32.exe user32.dll, UpdatePerUserSystemParameters


    # Show File Extensions
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -value 0

    # Show Hidden Folders
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -value 1
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowSuperHidden' -value 1

    # Do not show Explorer Tabs in ALT+TAB
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'MultiTaskingAltTabFilter' -value 3

    # Make Windows Explorer use 'Details' View
    new-psDrive -name HKCR -psProvider registry -root HKEY_CLASSES_ROOT
    #Remove-Item 'HKCR:\Local Settings\Software\Microsoft\Windows\Shell\Bags' -Recurse -Force
    #Remove-Item 'HKCR:\Local Settings\Software\Microsoft\Windows\Shell\BagsMRU' -Recurse -Force

    New-Item -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\Defaults' -Force
    Set-Itemproperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\Defaults' -Name 'Mode' -value 4

    # Enable Telnet Client
    Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient

    # Disable Windows Error Reporting
    Disable-WindowsErrorReporting

    # Disable Telemetry
    Set-Service -Name "DiagTrack" -StartupType Disabled



}

Restart-VM -VM $VM -Wait -For IPAddress -Force
Wait-VMAccess -VMName $VM.Name -Credential $VM_Admin_Login

# Initialize the Data Drive
Write-Host "Initializing the Data Drive..."
Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
    # Format the Data Drive and assign the drive letter.
    $VM_Hardware_DataDrive_Letter = $Using:VM_Hardware_DataDrive_Letter

    $Drive_Big = Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'}

    Initialize-Disk $Drive_Big.Number

    New-Partition -DiskNumber $Drive_Big.Number -UseMaximumSize -DriveLetter $VM_Hardware_DataDrive_Letter

    Format-Volume -FileSystem NTFS -DriveLetter $VM_Hardware_DataDrive_Letter
}

$CachePath = "$($VM_Hardware_DataDrive_Letter):\REPOSITORY"

Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
    $CachePath = $Using:CachePath
    mkdir $CachePath -Force
}






if($Install_Workstation_Development) {
    $Install_App__Shared = $true

    $Install_App_AutoIt = $true
    $Install_App_AzureStorageExplorer = $true
    $Install_App_BeyondCompare = $true
    $Install_App_BgInfo = $true
    $Install_App_CamtasiaStudio = $true
    $Install_App_DbBrowserForSqlite = $true
    $Install_App_DvorakSharp = $true
    $Install_App_Fiddler = $true
    $Install_App_FoxitPdfReader = $true
    $Install_App_FullConvert = $true
    $Install_App_GoogleDrive = $true
    $Install_App_HexWorkShop = $true
    $Install_App_IconGenerator = $true
    $Install_App_Insomnia = $true
    $Install_App_JustDecompile = $true
    $Install_App_LightShot = $true
    $Install_App_NotePadPlusPlus = $true
    $Install_App_Proxifier = $true
    $Install_App_SevenZip = $true
    $Install_App_SnagIt = $true
    $Install_App_SqlServer = $true
    $Install_App_SqlServerManagementStudio = $true
    $Install_App_Start11 = $true
    $Install_App_TeamViewer = $true
    $Install_App_VisualStudioCode = $true
    $Install_App_VisualStudioPro = $true

    $UnInstall_App_DefaultApps = $true
}

if($Install_Workstation_Migration) {
    $Install_App__Shared = $true

    $Install_App_BgInfo = $true
    $Install_App_DbBrowserForSqlite = $true
    $Install_App_Fiddler = $true
    $Install_App_FullConvert = $true
    $Install_App_GoogleDrive = $true
    $Install_App_NotePadPlusPlus = $true
    $Install_App_SevenZip = $true
    $Install_App_SqlServer = $true
    $Install_App_SqlServerManagementStudio = $true
    $Install_App_TeamViewer = $true
    $Install_App_VisualStudioCode = $true
    $Install_App_VisualStudioPro = $true

    $UnInstall_App_DefaultApps = $true
}

if($Install_Workstation_Desktop){
    $Install_App__Shared = $true

    $Install_App_BgInfo = $true
    $Install_App_DbBrowserForSqlite = $true
    $Install_App_FasterSuite = $true
    $Install_App_Fiddler = $true
    $Install_App_FoxitPdfReader = $true
    $Install_App_NotePadPlusPlus = $true
    $Install_App_SevenZip = $true
    $Install_App_TeamViewer = $true

    $UnInstall_App_DefaultApps = $true
}

#Start Installing Apps...
Write-Host "Installing Apps..."

#-------Install Software
if ($Install_App__Shared) {
    Write-Host "Installing: Shared OS Components"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://download.visualstudio.microsoft.com/download/pr/7331f052-6c2d-4890-8041-8058fee5fb0f/CE6593A1520591E7DEA2B93FD03116E3FC3B3821A0525322B0A430FAA6B3C0B4/VC_redist.x64.exe'
        $App_CachePath = "$($CachePath)\VisualCPlusPlusRuntimeInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_AutoIt) {
    Write-Host "Installing: AutoIt"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://www.autoitscript.com/files/autoit3/autoit-v3-setup.zip'
        $App_CachePath = "$($CachePath)\AutoItInstaller.zip"
        $App_Installer = "$($CachePath)\AutoIt-V3-Setup.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        Expand-Archive $App_CachePath -DestinationPath $CachePath -Force

        $Proc = Start-Process -PassThru $App_Installer -ArgumentList '/S'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_AzureStorageExplorer) {
    Write-Host "Installing: Azure Storage Explorer"
    Write-Host "       ETA: 01:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://go.microsoft.com/fwlink/?LinkId=708343&clcid=0x409'
        $App_CachePath = "$($CachePath)\AzureStorageExplorerInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/VERYSILENT /NORESTART /ALLUSERS'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_BgInfo) {
    Write-Host "Installing: BgInfo"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://live.sysinternals.com/Bginfo.exe'
        $App_CachePath = "$($CachePath)\BgInfo.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath

        $Config_DownloadUri = 'https://github.com/MediatedCommunications/UniversalMigrator.MigrationWorkstation/raw/main/BgInfo.bgi'
        $Config_CachePath = "$($CachePath)\BgInfo.bgi"
        Invoke-WebRequest -Uri $Config_DownloadUri -OutFile $Config_CachePath


        $App_InstallFolder = "$($env:ProgramFiles)\SysInternals"
        
        $App_InstallPath = "$($App_InstallFolder)\BgInfo.exe"
        $Config_InstallPath = "$($App_InstallFolder)\BgInfo.bgi"


        MkDir $App_InstallFolder
        Copy-Item $App_CachePath $App_InstallPath
        Copy-Item $Config_CachePath $Config_InstallPath

        New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name BgInfo -Value '"$($App_InstallPath)" "$($Config_InstallPath)" /accepteula /timer:00 /silent'

    }

}

#-------Install Software
if ($Install_App_BeyondCompare) {
    Write-Host "Installing: Beyond Compare"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://www.scootersoftware.com/BCompareSetup.exe'
        $App_CachePath = "$($CachePath)\BeyondCompareInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/SILENT'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_CamtasiaStudio) {
    Write-Host "Installing: Camtasia Studio"
    Write-Host "       ETA: 02:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://download.techsmith.com/camtasiastudio/releases/camtasia.msi'
        $App_CachePath = "$($CachePath)\CamtasiaStudioInstaller.msi"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath 
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_DbBrowserForSqlite) {
    Write-Host "Installing: DbBrowser for Sqlite"
    Write-Host "       ETA: 00:30 Minutes"


    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://download.sqlitebrowser.org/DB.Browser.for.SQLite-3.12.2-win64.msi'
        $App_CachePath = "$($CachePath)\DbBrowserForSqliteInstaller.msi"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart SHORTCUT_SQLITE_DESKTOP=1 SHORTCUT_SQLITE_PROGRAMMENU=1'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_DvorakSharp) {
    Write-Host "Installing: Dvorak# Keyboard"
    Write-Host "       ETA: 00:30 Minutes"


    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://github.com/MediatedCommunications/UniversalMigrator.MigrationWorkstation/raw/main/KbdEditInstallerDvorak%23.exe'
        $App_CachePath = "$($CachePath)\DvorakSharp.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        # $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart SHORTCUT_SQLITE_DESKTOP=1 SHORTCUT_SQLITE_PROGRAMMENU=1'
        # $Proc.WaitForExit()

    }

}



#-------Install Software
if ($Install_App_FasterSuite) {
    Write-Host "Installing: Faster Suite"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://get.fasterlaw.com/alphadrive/windows/stable/fastersuite.windows.setup.exe'
        $App_CachePath = "$($CachePath)\FasterSuiteInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath
        $Proc.WaitForExit()

    }

}



#-------Install Software
if ($Install_App_Fiddler) {
    Write-Host "Installing: Fiddler Classic"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://telerik-fiddler.s3.amazonaws.com/fiddler/FiddlerSetup.exe'
        $App_CachePath = "$($CachePath)\FiddlerClassicInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/S'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_FoxitPdfReader) {
    Write-Host "Installing: Foxit Pdf Reader"
    Write-Host "       ETA: 02:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://cdn01.foxitsoftware.com/product/reader/desktop/win/12.0.0/FoxitPDFReader1201_enu_Setup_Prom.exe'
        $App_CachePath = "$($CachePath)\FoxitPdfReaderInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/silent'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_FullConvert) {
    Write-Host "Installing: Full Convert"
    Write-Host "       ETA: 02:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        # $CachePath = $Using:CachePath
        # $App_DownloadUri = 'https://full-convert-deploy.azureedge.net/SetupFullConvert22.08.1666.exe'
        # $App_CachePath = "$($CachePath)\FullConvertInstaller.exe"
        # Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath -Headers @{ 'Accept-Encoding' = 'gzip, deflate, br' }
        # $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/exenoui /quiet'
        # $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_GoogleDrive) {
    Write-Host "Installing: Google Drive"
    Write-Host "       ETA: 02:30 Minutes"


    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://dl.google.com/drive-file-stream/GoogleDriveSetup.exe'
        $App_CachePath = "$($CachePath)\GoogleDriveInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_HexWorkshop) {
    Write-Host "Installing: Hex Workshop"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'http://www.bpsoft.com/downloads/hw_v680.exe'
        $App_CachePath = "$($CachePath)\HexWorkshopInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_IconGenerator) {
    Write-Host "Installing: Icon Generator"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://www.axialis.com/downloads/IconGenerator-Free-2-05-64-bit-Eng.exe'
        $App_CachePath = "$($CachePath)\IconGeneratorInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/q'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_Insomnia) {
    Write-Host "Installing: Insomnia"
    Write-Host "       ETA: 01:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        # This one is wonky so we sleep
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://updates.insomnia.rest/downloads/windows/latest?app=com.insomnia.app&source=website'
        $App_CachePath = "$($CachePath)\InsomniaInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()
        
    }

}




#-------Install Software
if ($Install_App_LightShot) {
    Write-Host "Installing: LightShot"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        # This one has a wonky installer so we sleep
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://app.prntscr.com/build/setup-lightshot.exe'
        $App_CachePath = "$($CachePath)\LightShotInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/SILENT'
        $Proc.WaitForExit()
        
    }

}

#-------Install Software
if ($Install_App_NotePadPlusPlus) {
    Write-Host "Installing: NotePad++"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.5.8/npp.8.5.8.Installer.x64.exe'
        $App_CachePath = "$($CachePath)\NotepadPlusPlusInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/S'
        $Proc.WaitForExit()

    }

}

#-------Install Software
if ($Install_App_Proxifier) {
    Write-Host "Installing: Proxifier"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://www.proxifier.com/download/ProxifierSetup.exe'
        $App_CachePath = "$($CachePath)\ProxifierInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru -Wait $App_CachePath -ArgumentList '/SILENT'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_SevenZip) {
    Write-Host "Installing: 7-Zip"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://www.7-zip.org/a/7z2301-x64.exe'
        $App_CachePath = "$($CachePath)\SevenZipInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/S'
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_Skype) {
    Write-Host "Installing: Skype"
    Write-Host "       ETA: 01:00 Minutes"


    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        # This one is wonky and needs a different security protocol.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://go.skype.com/windows.desktop.download'
        $App_CachePath = "$($CachePath)\SkypeInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/VERYSILENT'
        $Proc.WaitForExit()
        
    }

}



#-------Install Software
if ($Install_App_Slack) {
    Write-Host "Installing: Slack"
    Write-Host "       ETA: 00:30 Minutes"


    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        #NOTE:  Slack will not appear until restarting the PC.
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://slack.com/ssb/download-win64-msi-legacy'
        $App_CachePath = "$($CachePath)\SlackInstaller.msi"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru -Wait $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

    Restart-VM -VM $VM -Wait -For IPAddress -Force

}




#-------Install Software
if ($Install_App_SnagIt) {
    Write-Host "Installing: SnagIt"
    Write-Host "       ETA: 02:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://download.techsmith.com/snagit/releases/snagit.msi'
        $App_CachePath = "$($CachePath)\SnagItInstaller.msi"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()

    }

}


#-------Install Software
#Duration:  11.0 Minutes
if ($Install_App_SqlServer) {

    Write-Host "Installing: SQL Server"
    Write-Host "       ETA: 11:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $VM_Hardware_DataDrive_Letter = $Using:VM_Hardware_DataDrive_Letter
        $VM_Password = $Using:VM_Password
        
        $CachePath = $Using:CachePath

        $App_DownloadUri = 'https://go.microsoft.com/fwlink/p/?linkid=2215158'
        $App_CachePath = "$($CachePath)\SqlServerInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath


        Start-Process $App_CachePath -argumentlist "/ACTION=DOWNLOAD /MEDIATYPE=ISO /VERBOSE /QUIET /MEDIAPATH=$($CachePath)" -Wait
        $App_IsoPath = "$($CachePath)\SQLServer2022-x64-ENU-Dev.iso"
        $MountResults = Mount-DiskImage -ImagePath $App_IsoPath
        $MountDrive = ($MountResults | Get-Volume).DriveLetter

        $App_IsoInstaller = "$($MountDrive):\Setup.exe"

        $App_Dir_MDF = "$($VM_Hardware_DataDrive_Letter):\DBs"
        $App_Dir_LDF = "$($VM_Hardware_DataDrive_Letter):\DBs"
        $App_Dir_BAK = "$($VM_Hardware_DataDrive_Letter):\DBs_BAK"

        mkdir -force $App_Dir_MDF
        mkdir -force $App_Dir_LDF
        mkdir -force $App_Dir_BAK
        
        $Proc = Start-Process -PassThru $App_IsoInstaller -argumentlist ('' + `
            ' /Q /IACCEPTSQLSERVERLICENSETERMS /ACTION=INSTALL' + `
            ' /INSTANCENAME=MSSQLSERVER /FEATURES=SQL,IS' + `
            ' /SQLSVCACCOUNT="NT AUTHORITY\SYSTEM"' + `
            ' /UPDATEENABLED=1 /UPDATESOURCE=MU /USEMICROSOFTUPDATE' + `
            ' /SECURITYMODE=SQL' + `
            " /SAPWD=$($VM_Password)" + `
            ' /SQLSYSADMINACCOUNTS="BUILTIN\Administrators" "Administrator"' + `
            ' /TCPENABLED=1 /NPENABLED=1 /FILESTREAMLEVEL=3 /FILESTREAMSHARENAME=FILESTREAM' + `
            " /SQLUSERDBDIR=$($App_Dir_MDF)" + `
            " /SQLUSERDBLOGDIR=$($App_Dir_LDF)" + `
            " /SQLBACKUPDIR=$($App_Dir_BAK)" + `
            ' ' + `
            '')

        $Proc.WaitForExit()

        Dismount-DiskImage $App_IsoPath

    }

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        Invoke-Sqlcmd -Query @"
            EXEC sp_configure 'backup compression default', 1 ;  
            RECONFIGURE;  
            GO
"@
    }


}


#-------Install Software
if ($Install_App_SqlServerManagementStudio) {

    Write-Host "Installing: SQL Server Management Studio"
    Write-Host "       ETA: 05:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://aka.ms/ssmsfullsetup'
        $App_CachePath = "$($CachePath)\SsmsInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/install /quiet /norestart' 
        $Proc.WaitForExit()

    }

}


#-------Install Software
if ($Install_App_Start11) {

    Write-Host "Installing: Start11"
    Write-Host "       ETA: 01:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        # Wonky Installer.  Must use sleep.
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://cdn.stardock.us/downloads/public/software/start/Start11_setup.exe'
        $App_CachePath = "$($CachePath)\Start11Installer.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/S'
        $Proc.WaitForExit()
        
    }
}

#-------Install Software
if ($Install_App_TeamViewer) {

    Write-Host "Installing: TeamViewer"
    Write-Host "       ETA: 01:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe'
        $App_CachePath = "$($CachePath)\TeamViewerInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/S'
        $Proc.WaitForExit()
        
    }

}

if ($Install_App_VisualStudioCode) {

    Write-Host "Installing: Visual Studio Code"
    Write-Host "       ETA: 01:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user'
        $App_CachePath = "$($CachePath)\VisualStudioCodeInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/VERYSILENT'
        $Proc.WaitForExit()

    }
    
    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        code --install-extension ms-vscode.PowerShell    
    }

    

}

#-------Install Software
if ($Install_App_VisualStudioPro) {

    Write-Host "Installing: Visual Studio Pro"
    Write-Host "       ETA: 40:00 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://c2rsetup.officeapps.live.com/c2r/downloadVS.aspx?sku=professional&channel=Release&version=VS2022&source=VSLandingPage&includeRecommended=true&cid=2030:feea75e0f248468aa6dbe073cb92bcc9'
        $App_CachePath = "$($CachePath)\VisualStudioProInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru -Wait $App_CachePath -argumentlist ('' + `
            ' --quiet' + `
            ' --installWhileDownloading --includeRecommended' + `
            ' --add Microsoft.VisualStudio.Workload.ManagedDesktop' + `
            ' --add Microsoft.VisualStudio.Workload.NetWeb' + `
            ' --add Microsoft.VisualStudio.Workload.NetCrossPlat' + `
            ' ' + `
            '')
        $Proc.WaitForExit()

        
    }

}


#-------Install Software
if ($Install_App_WhatPulse) {
    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        Write-Host "Installing: WhatPulse"
        Write-Host "       ETA: 00:30 Minutes"

        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://cf-keycdn.whatpulse.org/latest/windows/whatpulse-win-latest.exe'
        $App_CachePath = "$($CachePath)\WhatPulseInstaller.exe"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList 'install --default-answer --accept-licenses --confirm-command'
        $Proc.WaitForExit()

    }

}



#-------Install Software
#Duration:  0.5 Minutes
if ($Install_App_Zoom) {
    Write-Host "Installing: Zoom"
    Write-Host "       ETA: 00:30 Minutes"

    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {

        $CachePath = $Using:CachePath
        $App_DownloadUri = 'https://zoom.us/client/latest/ZoomInstallerFull.msi'
        $App_CachePath = "$($CachePath)\ZoomInstaller.msi"
        Invoke-WebRequest -Uri $App_DownloadUri -OutFile $App_CachePath
        $Proc = Start-Process -PassThru $App_CachePath -ArgumentList '/quiet /norestart'
        $Proc.WaitForExit()
        
    }
}


#-------Remove Software
#Duration:  0.5 Minutes
if($UnInstall_App_DefaultApps){
    Write-Host "Uninstalling Bloatware..."
    Invoke-Command -VMName $VM.Name -Credential $VM_Admin_Login -ScriptBlock {
        
        Get-AppxPackage -allusers Microsoft.WindowsMaps* | Remove-AppPackage -allusers
        Get-AppxPackage -allusers Microsoft.WindowsCamera* | Remove-AppPackage -allusers
        Get-AppxPackage -allusers Microsoft.Windows.Photos* | Remove-AppPackage -allusers
        Get-AppxPackage -allusers Microsoft.ZuneMusic* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.ZuneVideo* | Remove-AppPackage -allusers
        Get-AppxPackage -allusers Microsoft.MicrosoftSolitaireCollection* | Remove-AppPackage -allusers
        Get-AppxPackage -allusers Microsoft.Office.OneNote* | Remove-AppxPackage -allusers
        
        Get-AppxPackage -allusers Microsoft.Xbox.TCUI* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.XboxApp* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.XboxGameOverlay* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.XboxGamingOverlay* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.XboxIdentityProvider* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.YourPhone* | Remove-AppxPackage -allusers

        Get-AppxPackage -AllUsers *CandyCrush* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Duolingo* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *EclipseManager* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Facebook* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *king.com.FarmHeroesSaga* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Flipboard* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *HiddenCityMysteryofShadows* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *HuluLLC.HuluPlus* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Pandora* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Plex* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *ROBLOXCORPORATION.ROBLOX* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Spotify* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Netflix* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Microsoft.SkypeApp* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Twitter* | Remove-AppxPackage -allusers
        Get-AppxPackage -AllUsers *Wunderlist* | Remove-AppxPackage -allusers
        Get-AppxPackage -allusers Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage -allusers

    }
}

Restart-VM -VM $VM -Wait -For IPAddress -Force

Write-Host "Setup Complete!"
