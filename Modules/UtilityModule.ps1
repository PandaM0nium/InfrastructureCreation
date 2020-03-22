##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

## Variables: Toolkit Name
[string]$appDeployToolkitName = 'PSAppDeployToolkit'
[string]$appDeployMainScriptFriendlyName = 'App Deploy Toolkit Main'

## Variables: Script Info
[version]$appDeployMainScriptVersion = [version]'3.6.8'
[version]$appDeployMainScriptMinimumConfigVersion = [version]'3.6.8'
[string]$appDeployMainScriptDate = '02/05/2016'
[hashtable]$appDeployMainScriptParameters = $PSBoundParameters

## Variables: Datetime and Culture
[datetime]$currentDateTime = Get-Date
[string]$currentTime = Get-Date -Date $currentDateTime -UFormat '%T'
[string]$currentDate = Get-Date -Date $currentDateTime -UFormat '%d-%m-%Y'
[timespan]$currentTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now)
[Globalization.CultureInfo]$culture = Get-Culture
[string]$currentLanguage = $culture.TwoLetterISOLanguageName.ToUpper()

## Variables: Environment Variables
[psobject]$envHost = $Host
[psobject]$envShellFolders = Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction 'SilentlyContinue'
[string]$envAllUsersProfile = $env:ALLUSERSPROFILE
[string]$envAppData = [Environment]::GetFolderPath('ApplicationData')
[string]$envArchitecture = $env:PROCESSOR_ARCHITECTURE
[string]$envCommonProgramFiles = [Environment]::GetFolderPath('CommonProgramFiles')
[string]$envCommonProgramFilesX86 = ${env:CommonProgramFiles(x86)}
[string]$envCommonDesktop   = $envShellFolders | Select-Object -ExpandProperty 'Common Desktop' -ErrorAction 'SilentlyContinue'
[string]$envCommonDocuments = $envShellFolders | Select-Object -ExpandProperty 'Common Documents' -ErrorAction 'SilentlyContinue'
[string]$envCommonPrograms  = $envShellFolders | Select-Object -ExpandProperty 'Common Programs' -ErrorAction 'SilentlyContinue'
[string]$envCommonStartMenu = $envShellFolders | Select-Object -ExpandProperty 'Common Start Menu' -ErrorAction 'SilentlyContinue'
[string]$envCommonStartUp   = $envShellFolders | Select-Object -ExpandProperty 'Common Startup' -ErrorAction 'SilentlyContinue'
[string]$envCommonTemplates = $envShellFolders | Select-Object -ExpandProperty 'Common Templates' -ErrorAction 'SilentlyContinue'
[string]$envComputerName = [Environment]::MachineName.ToUpper()
[string]$envComputerNameFQDN = ([Net.Dns]::GetHostEntry('localhost')).HostName
[string]$envHomeDrive = $env:HOMEDRIVE
[string]$envHomePath = $env:HOMEPATH
[string]$envHomeShare = $env:HOMESHARE
[string]$envLocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
[string[]]$envLogicalDrives = [Environment]::GetLogicalDrives()
[string]$envProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
[string]$envProgramFilesX86 = ${env:ProgramFiles(x86)}
[string]$envProgramData = [Environment]::GetFolderPath('CommonApplicationData')
[string]$envPublic = $env:PUBLIC
[string]$envSystemDrive = $env:SYSTEMDRIVE
[string]$envSystemRoot = $env:SYSTEMROOT
[string]$envTemp = [IO.Path]::GetTempPath()
[string]$envUserCookies = [Environment]::GetFolderPath('Cookies')
[string]$envUserDesktop = [Environment]::GetFolderPath('DesktopDirectory')
[string]$envUserFavorites = [Environment]::GetFolderPath('Favorites')
[string]$envUserInternetCache = [Environment]::GetFolderPath('InternetCache')
[string]$envUserInternetHistory = [Environment]::GetFolderPath('History')
[string]$envUserMyDocuments = [Environment]::GetFolderPath('MyDocuments')
[string]$envUserName = [Environment]::UserName
[string]$envUserPictures = [Environment]::GetFolderPath('MyPictures')
[string]$envUserProfile = $env:USERPROFILE
[string]$envUserSendTo = [Environment]::GetFolderPath('SendTo')
[string]$envUserStartMenu = [Environment]::GetFolderPath('StartMenu')
[string]$envUserStartMenuPrograms = [Environment]::GetFolderPath('Programs')
[string]$envUserStartUp = [Environment]::GetFolderPath('StartUp')
[string]$envUserTemplates = [Environment]::GetFolderPath('Templates')
[string]$envSystem32Directory = [Environment]::SystemDirectory
[string]$envWinDir = $env:WINDIR
#  Handle X86 environment variables so they are never empty
If (-not $envCommonProgramFilesX86) { [string]$envCommonProgramFilesX86 = $envCommonProgramFiles }
If (-not $envProgramFilesX86) { [string]$envProgramFilesX86 = $envProgramFiles }

## Variables: Domain Membership
[boolean]$IsMachinePartOfDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
[string]$envMachineWorkgroup = ''
[string]$envMachineADDomain = ''
[string]$envLogonServer = ''
[string]$MachineDomainController = ''
If ($IsMachinePartOfDomain) {
	[string]$envMachineADDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
	Try {
		[string]$envLogonServer = $env:LOGONSERVER | Where-Object { (($_) -and (-not $_.Contains('\\MicrosoftAccount'))) } | ForEach-Object { $_.TrimStart('\') } | ForEach-Object { ([Net.Dns]::GetHostEntry($_)).HostName }
		# If running in system context, fall back on the logonserver value stored in the registry
		If (-not $envLogonServer) { [string]$envLogonServer = Get-ItemProperty -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DCName' -ErrorAction 'SilentlyContinue' }
		[string]$MachineDomainController = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
	}
	Catch { }
}
Else {
	[string]$envMachineWorkgroup = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
}
[string]$envMachineDNSDomain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
[string]$envUserDNSDomain = $env:USERDNSDOMAIN | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
Try {
	[string]$envUserDomain = [Environment]::UserDomainName.ToUpper()
}
Catch { }

## Variables: Operating System
[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = [Environment]::OSVersion.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
[string]$envOSVersionRevision = $envOSVersion.Revision
[string]$envOSVersion = $envOSVersion.ToString()
#  Get the operating system type
[int32]$envOSProductType = $envOS.ProductType
[boolean]$IsServerOS = [boolean]($envOSProductType -eq 3)
[boolean]$IsDomainControllerOS = [boolean]($envOSProductType -eq 2)
[boolean]$IsWorkStationOS = [boolean]($envOSProductType -eq 1)
Switch ($envOSProductType) {
	3 { [string]$envOSProductTypeName = 'Server' }
	2 { [string]$envOSProductTypeName = 'Domain Controller' }
	1 { [string]$envOSProductTypeName = 'Workstation' }
	Default { [string]$envOSProductTypeName = 'Unknown' }
}
#  Get the OS Architecture
[boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
If ($Is64Bit) { [string]$envOSArchitecture = '64-bit' } Else { [string]$envOSArchitecture = '32-bit' }

## Variables: Current Process Architecture
[boolean]$Is64BitProcess = [boolean]([IntPtr]::Size -eq 8)
If ($Is64BitProcess) { [string]$psArchitecture = 'x64' } Else { [string]$psArchitecture = 'x86' }

## Variables: PowerShell And CLR (.NET) Versions
[hashtable]$envPSVersionTable = $PSVersionTable
#  PowerShell Version
[version]$envPSVersion = $envPSVersionTable.PSVersion
[string]$envPSVersionMajor = $envPSVersion.Major
[string]$envPSVersionMinor = $envPSVersion.Minor
[string]$envPSVersionBuild = $envPSVersion.Build
[string]$envPSVersionRevision = $envPSVersion.Revision
[string]$envPSVersion = $envPSVersion.ToString()
#  CLR (.NET) Version used by PowerShell
[version]$envCLRVersion = $envPSVersionTable.CLRVersion
[string]$envCLRVersionMajor = $envCLRVersion.Major
[string]$envCLRVersionMinor = $envCLRVersion.Minor
[string]$envCLRVersionBuild = $envCLRVersion.Build
[string]$envCLRVersionRevision = $envCLRVersion.Revision
[string]$envCLRVersion = $envCLRVersion.ToString()

## Variables: Permissions/Accounts
[Security.Principal.WindowsIdentity]$CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent()
[Security.Principal.SecurityIdentifier]$CurrentProcessSID = $CurrentProcessToken.User
[string]$ProcessNTAccount = $CurrentProcessToken.Name
[string]$ProcessNTAccountSID = $CurrentProcessSID.Value
[boolean]$IsAdmin = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544')
[boolean]$IsLocalSystemAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalSystemSid')
[boolean]$IsLocalServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalServiceSid')
[boolean]$IsNetworkServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'NetworkServiceSid')
[boolean]$IsServiceAccount = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-6')
[boolean]$IsProcessUserInteractive = [Environment]::UserInteractive
[string]$LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value
#  Check if script is running in session zero
If ($IsLocalSystemAccount -or $IsLocalServiceAccount -or $IsNetworkServiceAccount -or $IsServiceAccount) { $SessionZero = $true } Else { $SessionZero = $false }

## Variables: Script Name and Script Paths
[string]$scriptPath = $MyInvocation.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[string]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent
[string]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($invokingScript) {
	#  If this script was invoked by another script
	[string]$scriptParentPath = Split-Path -Path $invokingScript -Parent
}
Else {
	#  If this script was not invoked by another script, fall back to the directory one level above this script
	[string]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
}

## Variables: App Deploy Script Dependency Files
[string]$appDeployLogoIcon = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitLogo.ico'
[string]$appDeployLogoBanner = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitBanner.png'
[string]$appDeployConfigFile = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitConfig.xml'
[string]$appDeployCustomTypesSourceCode = Join-Path -Path $scriptRoot -ChildPath 'AppDeployToolkitMain.cs'
#  App Deploy Optional Extensions File
[string]$appDeployToolkitDotSourceExtensions = 'AppDeployToolkitExtensions.ps1'
#  Check that dependency files are present
If (-not (Test-Path -LiteralPath $appDeployLogoIcon -PathType 'Leaf')) { Throw 'App Deploy logo icon file not found.' }
If (-not (Test-Path -LiteralPath $appDeployLogoBanner -PathType 'Leaf')) { Throw 'App Deploy logo banner file not found.' }
If (-not (Test-Path -LiteralPath $appDeployConfigFile -PathType 'Leaf')) { Throw 'App Deploy XML configuration file not found.' }
If (-not (Test-Path -LiteralPath $appDeployCustomTypesSourceCode -PathType 'Leaf')) { Throw 'App Deploy custom types source code file not found.' }

## Import variables from XML configuration file
[Xml.XmlDocument]$xmlConfigFile = Get-Content -LiteralPath $AppDeployConfigFile
[Xml.XmlElement]$xmlConfig = $xmlConfigFile.AppDeployToolkit_Config
#  Get Config File Details
[Xml.XmlElement]$configConfigDetails = $xmlConfig.Config_File
[string]$configConfigVersion = [version]$configConfigDetails.Config_Version
[string]$configConfigDate = $configConfigDetails.Config_Date
#  Get Toolkit Options
[Xml.XmlElement]$xmlToolkitOptions = $xmlConfig.Toolkit_Options
[boolean]$configToolkitRequireAdmin = [boolean]::Parse($xmlToolkitOptions.Toolkit_RequireAdmin)
[string]$configToolkitTempPath = $ExecutionContext.InvokeCommand.ExpandString($xmlToolkitOptions.Toolkit_TempPath)
[string]$configToolkitRegPath = $xmlToolkitOptions.Toolkit_RegPath
[string]$configToolkitLogDir = $ExecutionContext.InvokeCommand.ExpandString($xmlToolkitOptions.Toolkit_LogPath)
[boolean]$configToolkitCompressLogs = [boolean]::Parse($xmlToolkitOptions.Toolkit_CompressLogs)
[string]$configToolkitLogStyle = $xmlToolkitOptions.Toolkit_LogStyle
[double]$configToolkitLogMaxSize = $xmlToolkitOptions.Toolkit_LogMaxSize
[boolean]$configToolkitLogWriteToHost = [boolean]::Parse($xmlToolkitOptions.Toolkit_LogWriteToHost)
[boolean]$configToolkitLogDebugMessage = [boolean]::Parse($xmlToolkitOptions.Toolkit_LogDebugMessage)
#  Get MSI Options
[Xml.XmlElement]$xmlConfigMSIOptions = $xmlConfig.MSI_Options
[string]$configMSILoggingOptions = $xmlConfigMSIOptions.MSI_LoggingOptions
[string]$configMSIInstallParams = $xmlConfigMSIOptions.MSI_InstallParams
[string]$configMSISilentParams = $xmlConfigMSIOptions.MSI_SilentParams
[string]$configMSIUninstallParams = $xmlConfigMSIOptions.MSI_UninstallParams
[string]$configMSILogDir = $ExecutionContext.InvokeCommand.ExpandString($xmlConfigMSIOptions.MSI_LogPath)
[int32]$configMSIMutexWaitTime = $xmlConfigMSIOptions.MSI_MutexWaitTime
#  Get UI Options
[Xml.XmlElement]$xmlConfigUIOptions = $xmlConfig.UI_Options
[string]$configInstallationUILanguageOverride = $xmlConfigUIOptions.InstallationUI_LanguageOverride
[boolean]$configShowBalloonNotifications = [boolean]::Parse($xmlConfigUIOptions.ShowBalloonNotifications)
[int32]$configInstallationUITimeout = $xmlConfigUIOptions.InstallationUI_Timeout
[int32]$configInstallationUIExitCode = $xmlConfigUIOptions.InstallationUI_ExitCode
[int32]$configInstallationDeferExitCode = $xmlConfigUIOptions.InstallationDefer_ExitCode
[int32]$configInstallationPersistInterval = $xmlConfigUIOptions.InstallationPrompt_PersistInterval
[int32]$configInstallationRestartPersistInterval = $xmlConfigUIOptions.InstallationRestartPrompt_PersistInterval
[int32]$configInstallationPromptToSave = $xmlConfigUIOptions.InstallationPromptToSave_Timeout
#  Define ScriptBlock for Loading Message UI Language Options (default for English if no localization found)
[scriptblock]$xmlLoadLocalizedUIMessages = {
	#  If a user is logged on, then get primary UI language for logged on user (even if running in session 0)
	If ($RunAsActiveUser) {
		#  Read language defined by Group Policy
		If (-not $HKULanguages) {
			[string[]]$HKULanguages = Get-RegistryKey -Key 'HKLM:SOFTWARE\Policies\Microsoft\MUI\Settings' -Value 'PreferredUILanguages'
		}
		If (-not $HKULanguages) {
			[string[]]$HKULanguages = Get-RegistryKey -Key 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -Value 'PreferredUILanguages' -SID $RunAsActiveUser.SID
		}
		#  Read language for Win Vista & higher machines
		If (-not $HKULanguages) {
			[string[]]$HKULanguages = Get-RegistryKey -Key 'HKCU\Control Panel\Desktop' -Value 'PreferredUILanguages' -SID $RunAsActiveUser.SID
		}
		If (-not $HKULanguages) {
			[string[]]$HKULanguages = Get-RegistryKey -Key 'HKCU\Control Panel\Desktop\MuiCached' -Value 'MachinePreferredUILanguages' -SID $RunAsActiveUser.SID
		}
		If (-not $HKULanguages) {
			[string[]]$HKULanguages = Get-RegistryKey -Key 'HKCU\Control Panel\International' -Value 'LocaleName' -SID $RunAsActiveUser.SID
		}
		#  Read language for Win XP machines
		If (-not $HKULanguages) {
			[string]$HKULocale = Get-RegistryKey -Key 'HKCU\Control Panel\International' -Value 'Locale' -SID $RunAsActiveUser.SID
			If ($HKULocale) {
				[int32]$HKULocale = [Convert]::ToInt32('0x' + $HKULocale, 16)
				[string[]]$HKULanguages = ([Globalization.CultureInfo]($HKULocale)).Name
			}
		}
		If ($HKULanguages) {
			[Globalization.CultureInfo]$PrimaryWindowsUILanguage = [Globalization.CultureInfo]($HKULanguages[0])
			[string]$HKUPrimaryLanguageShort = $PrimaryWindowsUILanguage.TwoLetterISOLanguageName.ToUpper()
			
			#  If the detected language is Chinese, determine if it is simplified or traditional Chinese
			If ($HKUPrimaryLanguageShort -eq 'ZH') {
				If ($PrimaryWindowsUILanguage.EnglishName -match 'Simplified') {
					[string]$HKUPrimaryLanguageShort = 'ZH-Hans'
				}
				If ($PrimaryWindowsUILanguage.EnglishName -match 'Traditional') {
					[string]$HKUPrimaryLanguageShort = 'ZH-Hant'
				}
			}
			
			#  If the detected language is Portuguese, determine if it is Brazilian Portuguese
			If ($HKUPrimaryLanguageShort -eq 'PT') {
				If ($PrimaryWindowsUILanguage.ThreeLetterWindowsLanguageName -eq 'PTB') {
					[string]$HKUPrimaryLanguageShort = 'PT-BR'
				}
			}
		}
	}
	
	If ($HKUPrimaryLanguageShort) {
		#  Use the primary UI language of the logged in user
		[string]$xmlUIMessageLanguage = "UI_Messages_$HKUPrimaryLanguageShort"
	}
	Else {
		#  Default to UI language of the account executing current process (even if it is the SYSTEM account)
		[string]$xmlUIMessageLanguage = "UI_Messages_$currentLanguage"
	}
	#  Default to English if the detected UI language is not available in the XMl config file
	If (-not ($xmlConfig.$xmlUIMessageLanguage)) { [string]$xmlUIMessageLanguage = 'UI_Messages_EN' }
	#  Override the detected language if the override option was specified in the XML config file
	If ($configInstallationUILanguageOverride) { [string]$xmlUIMessageLanguage = "UI_Messages_$configInstallationUILanguageOverride" }
	
	[Xml.XmlElement]$xmlUIMessages = $xmlConfig.$xmlUIMessageLanguage
	[string]$configDiskSpaceMessage = $xmlUIMessages.DiskSpace_Message
	[string]$configBalloonTextStart = $xmlUIMessages.BalloonText_Start
	[string]$configBalloonTextComplete = $xmlUIMessages.BalloonText_Complete
	[string]$configBalloonTextRestartRequired = $xmlUIMessages.BalloonText_RestartRequired
	[string]$configBalloonTextFastRetry = $xmlUIMessages.BalloonText_FastRetry
	[string]$configBalloonTextError = $xmlUIMessages.BalloonText_Error
	[string]$configProgressMessageInstall = $xmlUIMessages.Progress_MessageInstall
	[string]$configProgressMessageUninstall = $xmlUIMessages.Progress_MessageUninstall
	[string]$configClosePromptMessage = $xmlUIMessages.ClosePrompt_Message
	[string]$configClosePromptButtonClose = $xmlUIMessages.ClosePrompt_ButtonClose
	[string]$configClosePromptButtonDefer = $xmlUIMessages.ClosePrompt_ButtonDefer
	[string]$configClosePromptButtonContinue = $xmlUIMessages.ClosePrompt_ButtonContinue
	[string]$configClosePromptButtonContinueTooltip = $xmlUIMessages.ClosePrompt_ButtonContinueTooltip
	[string]$configClosePromptCountdownMessage = $xmlUIMessages.ClosePrompt_CountdownMessage
	[string]$configDeferPromptWelcomeMessage = $xmlUIMessages.DeferPrompt_WelcomeMessage
	[string]$configDeferPromptExpiryMessage = $xmlUIMessages.DeferPrompt_ExpiryMessage
	[string]$configDeferPromptWarningMessage = $xmlUIMessages.DeferPrompt_WarningMessage
	[string]$configDeferPromptRemainingDeferrals = $xmlUIMessages.DeferPrompt_RemainingDeferrals
	[string]$configDeferPromptDeadline = $xmlUIMessages.DeferPrompt_Deadline
	[string]$configBlockExecutionMessage = $xmlUIMessages.BlockExecution_Message
	[string]$configDeploymentTypeInstall = $xmlUIMessages.DeploymentType_Install
	[string]$configDeploymentTypeUnInstall = $xmlUIMessages.DeploymentType_UnInstall
	[string]$configRestartPromptTitle = $xmlUIMessages.RestartPrompt_Title
	[string]$configRestartPromptMessage = $xmlUIMessages.RestartPrompt_Message
	[string]$configRestartPromptMessageTime = $xmlUIMessages.RestartPrompt_MessageTime
	[string]$configRestartPromptMessageRestart = $xmlUIMessages.RestartPrompt_MessageRestart
	[string]$configRestartPromptTimeRemaining = $xmlUIMessages.RestartPrompt_TimeRemaining
	[string]$configRestartPromptButtonRestartLater = $xmlUIMessages.RestartPrompt_ButtonRestartLater
	[string]$configRestartPromptButtonRestartNow = $xmlUIMessages.RestartPrompt_ButtonRestartNow
	[string]$configWelcomePromptCountdownMessage = $xmlUIMessages.WelcomePrompt_CountdownMessage
	[string]$configWelcomePromptCustomMessage = $xmlUIMessages.WelcomePrompt_CustomMessage
}

## Variables: Script Directories
[string]$dirFiles = Join-Path -Path $scriptParentPath -ChildPath 'Files'
[string]$dirSupportFiles = Join-Path -Path $scriptParentPath -ChildPath 'SupportFiles'
[string]$dirAppDeployTemp = Join-Path -Path $configToolkitTempPath -ChildPath $appDeployToolkitName

## Set the deployment type to "Install" if it has not been specified
If (-not $deploymentType) { [string]$deploymentType = 'Install' }

## Variables: Executables
[string]$exeWusa = 'wusa.exe' # Installs Standalone Windows Updates
[string]$exeMsiexec = 'msiexec.exe' # Installs MSI Installers
[string]$exeSchTasks = "$envWinDir\System32\schtasks.exe" # Manages Scheduled Tasks

## Variables: RegEx Patterns
[string]$MSIProductCodeRegExPattern = '^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$'

## Variables: Registry Keys
#  Registry keys for native and WOW64 applications
[string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
If ($is64Bit) {
	[string]$regKeyLotusNotes = 'HKLM:SOFTWARE\Wow6432Node\Lotus\Notes'
}
Else {
	[string]$regKeyLotusNotes = 'HKLM:SOFTWARE\Lotus\Notes'
}
[string]$regKeyAppExecution = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

## COM Objects: Initialize
[__comobject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'SilentlyContinue'
[__comobject]$ShellApp = New-Object -ComObject 'Shell.Application' -ErrorAction 'SilentlyContinue'

## Variables: Reset/Remove Variables
[boolean]$msiRebootDetected = $false
[boolean]$BlockExecution = $false
[boolean]$installationStarted = $false
[boolean]$runningTaskSequence = $false
If (Test-Path -LiteralPath 'variable:welcomeTimer') { Remove-Variable -Name 'welcomeTimer' -Scope 'Script'}
#  Reset the deferral history
If (Test-Path -LiteralPath 'variable:deferHistory') { Remove-Variable -Name 'deferHistory' }
If (Test-Path -LiteralPath 'variable:deferTimes') { Remove-Variable -Name 'deferTimes' }
If (Test-Path -LiteralPath 'variable:deferDays') { Remove-Variable -Name 'deferDays' }

## Variables: System DPI Scale Factor
[scriptblock]$GetDisplayScaleFactor = {
	#  If a user is logged on, then get display scale factor for logged on user (even if running in session 0)
	[boolean]$UserDisplayScaleFactor = $false
	If ($RunAsActiveUser) {
		[int32]$dpiPixels = Get-RegistryKey -Key 'HKCU\Control Panel\Desktop\WindowMetrics' -Value 'AppliedDPI' -SID $RunAsActiveUser.SID
		If (-not ([string]$dpiPixels)) {
			[int32]$dpiPixels = Get-RegistryKey -Key 'HKCU\Control Panel\Desktop' -Value 'LogPixels' -SID $RunAsActiveUser.SID
		}
		[boolean]$UserDisplayScaleFactor = $true
	}
	If (-not ([string]$dpiPixels)) {
		#  This registry setting only exists if system scale factor has been changed at least once
		[int32]$dpiPixels = Get-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI' -Value 'LogPixels'
		[boolean]$UserDisplayScaleFactor = $false
	}
	Switch ($dpiPixels) {
		96 { [int32]$dpiScale = 100 }
		120 { [int32]$dpiScale = 125 }
		144 { [int32]$dpiScale = 150 }
		192 { [int32]$dpiScale = 200 }
		Default { [int32]$dpiScale = 100 }
	}
}
#endregion
