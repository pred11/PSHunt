<#
.SYNOPSIS 
	 
	Survey.ps1 is used to collect comprehensive information on the state of running processes, services, drivers along with additional configuration information relevant
	for discovering malware on a live host. 
	
	Project: PSHunt
	Author: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
	Company: Infocyte, Inc.
	License: Apache License 2.0
	Required Dependencies: PSReflect (@Mattifestation)
	Optional Dependencies: None
		
.DESCRIPTION 

	Survey.ps1 is used to collect comprehensive information on the state of running processes, services, drivers along with additional configuration information relevant
	for discovering malware on a live host.  
	
	Survey.ps1 should be ran with full local administrator privileges with SeDebug right.

	
.EXAMPLE  
 
    Usage: powershell -ExecutionPolicy bypass .\Survey.ps1
	
	Tip: The results (HostObject.xml) output can be imported manually into powershell via the following command:
		$var = Import-cliXML .\SurveyResults.xml
		Import it and manipulate it in dot notation.  Example: $myVariableName.ProcessList | format-table -auto	
		
#>
[CmdletBinding()]
Param(	
	[parameter(	Mandatory=$False)]
	[string]$SurveyOut="SurveyResults.xml",
	   
	[parameter(	Mandatory=$False,
			HelpMessage='Where to send the Survey results. Default=DropToDisk C:\Windows\temp\$SurveyOut.xml')]
	[ValidateSet('DropToDisk', 'HTTPPostback', 'FTPPostback')]	
	[String]$ReturnType = "DropToDisk",

	[parameter(	Mandatory=$False,
			HelpMessage='Where to send the Survey results.  Web or FTP address (i.e. http://www.myserver.com/upload/')]	
	[ValidateScript({ ($_ -eq $Null) -OR ($_ -match "/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/") -OR ($_ -match "/^(ftps?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/") })]	
	[String]$ReturnAddress,
	
	[parameter(	Mandatory=$False)]
	[System.Management.Automation.PSCredential]$WebCredentials
	)

#Requires -Version 2

#region Variables
# ====================================================
	$Version = 0.7
	
	#$ScriptPath = split-path -parent $MyInvocation.MyCommand.Definition
	# Find paths regardless of where/how script was run (sync scopes in Powershell and .NET enviroments)
	if ($MyInvocation.MyCommand.Path) {
	
		# If it is run as a script MyCommand.Path is your friend (won't work if run from a console) (if 3.0+ use $PSScriptRoot)
		$ScriptPath = $MyInvocation.MyCommand.Path
		$ScriptDir  = Split-Path -Parent $ScriptPath
		
		# Set .net current working directory to Powershell's working directory(scripts ran as SYSTEM will default to C:\Windows\System32\)
		[Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
	} else {
		# Just drop it in the temp folder
		$ScriptDir  = (Resolve-Path $env:windir\temp).Path
		[Environment]::CurrentDirectory = $ScriptDir
	}
	$OutPath = "$ScriptDir\$SurveyOut"
#endregion Variables

#region Initialization	
# ====================================================
	
	# Supress errors unless debugging
	if ((!$PSBoundParameters['verbose']) -AND (!$PSBoundParameters['debug'])) { 
		$ErrorActionPreference  = "SilentlyContinue"
		$DebugPreference = "SilentlyContinue"
		$ErrorView = "CategoryView"
	} 
	elseif ($PSBoundParameters['debug']) { 
		$ErrorActionPreference  = "Inquire"
		$DebugPreference = "Inquire"
		$ErrorView = "NormalView"
		Set-StrictMode -Version 2.0
	} 
	elseif ($PSBoundParameters['verbose']) { 
		$ErrorActionPreference  = "Continue"
		$DebugPreference = "ContinueSilently"
		$ErrorView = "CategoryView"
	}

	# Test Powershell and .NET versions
	function Local:Test-PSCompatibility {
		# Windows PowerShell 2.0 needs to be installed on Windows Server 2008 and Windows Vista. It is already installed on Windows Server 2008 R2 and Windows 7.
		# In Windows Vista SP2 and Windows Server 2008 SP2 the integrated version of the .NET Framework is version 3.0;   
		# in Windows 7 and Windows Server 2008 R2, the integrated version of the .NET Framework is version 3.5 SP1
		
		# These checks won't work in PS 1.0 but will in 2.0+, so just catch failures to find incompatibility.
		try {
			$VersionCheck = New-Object PSObject -Property @{
				PSVersion 		= $psversiontable.PSVersion.ToString()
				DotNetVersion 	= gci 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' | sort pschildname -Descending | select -First 1 -ExpandProperty pschildname
			}
			
			Write-Verbose "Powershell version: $VersionCheck.PSVersion"
			Write-Verbose "DotNet Version: $VersionCheck.DotNetVersion"
			return $VersionCheck
		} catch {
			Write-Warning "Must have Powershell 2.0 or higher"
			"ERROR: Script not compatible with Powershell 1.0" >> SurveyLog.txt
			del $ScriptPath
			#have to do this or it freezes:
			[System.Diagnostics.Process]::GetCurrentProcess().Kill()
		}									
	}

	$Null = Test-PSCompatibility
	
	# Initialize Crypto
	try { $MD5CryptoProvider = new-object -TypeName system.security.cryptography.MD5CryptoServiceProvider } catch { $MD5CryptoProvider = $null }
	try { $SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider } catch { $SHA1CryptoProvider = $null }
	try { $SHA256CryptoProvider = new-object -TypeName system.security.cryptography.SHA256CryptoServiceProvider } catch { $SHA256CryptoProvider = $null }
	
	$Global:CryptoProvider = New-Object PSObject -Property @{
		MD5CryptoProvider = $MD5CryptoProvider
		SHA1CryptoProvider = $SHA1CryptoProvider
		SHA256CryptoProvider = $SHA256CryptoProvider
	}

#endregion Initialization

#region Collector Functions 
# ====================================================


function Get-Processes {
	Write-Verbose "Getting ProcessList"
	
	# Get Processes 
	$processes = Get-WmiObject -Class Win32_Process
	
	$processList = @()	
	foreach ($process in $processes) {

		try {
			$Owner = $process.GetOwner().Domain.ToString() + "\"+ $process.GetOwner().User.ToString()
            $OwnerSID = $process.GetOwnerSid().Sid
		} catch {
			Write-Warning "Owner could not be determined for $($process.Caption) (PID $($process.ProcessId))" 
		}
		
        $thisProcess = New-Object PSObject -Property @{
			ProcessId			= [int]$process.ProcessId
			ParentProcessId		= [int]$process.ParentProcessId
			ParentProcessName 	= ($processes | where { $_.ProcessID -eq $process.ParentProcessId}).Caption
			SessionId			= [int]$process.SessionId
			Name				= $process.Caption
			Owner 				= $Owner
            OwnerSID            = $OwnerSID 
			PathName			= $process.ExecutablePath
			CommandLine			= $process.CommandLine
			CreationDate 		= $process.ConvertToDateTime($process.CreationDate)
			ModuleList 			= @()
		}
		
		if ($process.ExecutablePath) {
			# Get hashes and verify Signatures with Sigcheck
			$Signature = Invoke-Sigcheck $process.ExecutablePath -GetHashes | Select -Property * -ExcludeProperty Path
			$Signature.PSObject.Properties | Foreach-Object {
				$thisProcess | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -Force
			}
		}
		
		$processList += $thisProcess 
	}
	return $processList
}

# You are being soooo slow.  TODO: Change to only query WorkingSet (sure I'll miss paged stuff but if there is an active cnx, that prob won't happen... I think)
function Get-MemoryInjects {
<#
.SYNOPSIS

Grab memory regions indicative of Injected DLLs (Reflective DLL Injection, Process Overwrite, etc.)
Check for MZ headers and print all printable strings.

Author: Chris Gerritz(@singlethreaded)
Pulled Liberally from: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
                       Get-ProcessMemoryInfo
Optional Dependencies: 

.DESCRIPTION

Get-MemoryInjects reads every committed executable memory allocation and
checks for MZ headers, returns all printable strings. 

.PARAMETER ProcessID

Specifies the process ID.

.EXAMPLE

Get-Process | Get-MemoryInjects

.EXAMPLE

Get-Process cmd | Get-MemoryInjects
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Id')]
        [ValidateScript({Get-Process -Id $_})]
        [Int32]
        $ProcessID
    )

    BEGIN {
        $Mod = New-InMemoryModule -ModuleName MemoryInjects

        $FunctionDefinitions = @(
		    (func kernel32 GetLastError ([Int32]) @()),
            (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
            (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
            (func kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [Byte[]], [Int], [Int].MakeByRefType()) -SetLastError),
            (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
            (func kernel32 K32GetModuleFileNameEx ([Int]) @([Int], [IntPtr], [Text.StringBuilder], [Int]) -SetLastError),
			(func psapi GetModuleFileNameEx ([Int]) @([Int], [IntPtr], [Text.StringBuilder], [Int]) -SetLastError)
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32MemoryInjects'
        $Kernel32 = $Types['kernel32']
		$Psapi = $Types['psapi']
		# $Memory = @()
		
		#$SmallestSize = 4096
		$SmallestSize = 16384
		$MinStringSize = 4
    }
    
    PROCESS {
		# PROCESS_VM_READ (0x00000010) | PROCESS_QUERY_INFORMATION (0x00000400)
        $hProcess = $Kernel32::OpenProcess(0x410, $False, $ProcessID) # PROCESS_VM_READ (0x00000010)
		$ProcessName = (Get-Process -Id $ProcessId).Name
        $ProcessMemory = Get-ProcessMemoryInfo -ProcessID $ProcessID | where { 
			($_.State -eq 'MEM_COMMIT') -AND 
			($_.Type -eq "MEM_PRIVATE") -AND # When they use VirtualAlloc(Ex), Private memory is allocated. (fragmentation makes heap allocations hard to use for injection so we don't see it)
			($_.RegionSize -gt $SmallestSize) -AND # Lots of false positives are filtered out when we realize any malware with more than one function prob won't fit in 4kb.
			($_.Protect -match "EXECUTE") -AND # Looking only for sections currently marked executable.
			($_.Protect -notmatch "PAGE_GUARD") -AND
			($_.AllocationProtect -notmatch "PAGE_NOACCESS")
			}
		Write-Verbose "Process: $ProcessID MemObjects: $($ProcessMemory.count)"
        
		$ProcessMemory | % {
            $Allocation = $_

			$Bytes = New-Object Byte[]($Allocation.RegionSize)
			
			$PE = $false
			$BytesRead = 0
			$Result = $Kernel32::ReadProcessMemory($hProcess, $Allocation.BaseAddress, $Bytes, $Allocation.RegionSize, [Ref] $BytesRead)
						
			if ((-not $Result) -or ($BytesRead -ne $Allocation.RegionSize)) {
				Write-Warning "Unable to read 0x$($Allocation.BaseAddress.ToString('X16')) from PID $ProcessID. Size: 0x$($Allocation.RegionSize.ToString('X8'))"
			} else {
				
				# Get ModuleName from handle
				<#
				$FileNameSize = 255
				$StrBuilder = New-Object System.Text.StringBuilder $FileNameSize
				try {
					# Refer to http://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx+
					# This function may not be exported depending on the OS version.
					$null = $Kernel32::K32GetModuleFileNameEx($hProcess, $Allocation.BaseAddress, $StrBuilder, $FileNameSize)
				} catch {
					Write-Warning "Unable to call K32GetModuleFileNameEx"
					try {
						$null = $Psapi::GetModuleFileNameEx($hProcess, $Allocation.BaseAddress, $StrBuilder, $FileNameSize)
					} catch {
							Write-Warning "Unable to call Psapi::GetModuleFileNameEx"
					}
				}
				$ModuleName = $StrBuilder.ToString()
				#>
				
				# Check for PE Header
				# Write-Verbose "Checking for PE Header"
				try {
					$MZHeader = [System.Text.Encoding]::ASCII.GetString($Bytes[0..1])			
				}catch {
					Write-Warning "Could not convert first bytes of allocation to string"
				}
				try {
					# This might not be where the COFF header starts... consider this a placeholder till we start parsing PE Headers
					# https://en.wikipedia.org/wiki/Portable_Executable#/media/File:Portable_Executable_32_bit_Structure_in_SVG_fixed.svg
					$COFFHeader = [System.Text.Encoding]::ASCII.GetString($Bytes[264..265])
				}catch {
					Write-Warning "Could not convert first bytes of allocation to string"
				}				
				try {
					$ArrayPtr = [Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($Bytes, 0)
					$RawString = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ArrayPtr, 2)
				}catch {
					Write-Warning "Could not convert first bytes of allocation to string"
				}					
				Write-Verbose "First Bytes: ($MZHeader), RawString: ($RawString), COFF Header: ($COFFHeader)"
				if (( $MZHeader -eq 'MZ' ) -OR ($COFFHeader -eq 'PE') -OR ($RawString  -eq 'MZ')) {
					Write-Verbose "Found a potential INJECTED MODULE in ProcessID: $ProcessID"
					$PE = $true
				}
				
				# Get unique strings of section
				# Write-Verbose "Getting Strings"		
				# $Base64String = [System.Convert]::ToBase64String($ByteArray[0..$BytesRead])
				try { 
					$UTF8Strings = [System.Text.Encoding]::UTF8.GetString($Bytes[0..$BytesRead])
				} catch {
					Write-Warning "Could not convert bytes to UTF8"
				}
				
				try {
					$UnicodeStrings = [System.Text.Encoding]::Unicode.GetString($Bytes[0..$BytesRead])
				} catch {
					Write-Warning "Could not convert bytes to Unicode"
				}	
				
				$Strings = @()
				$Strings += "$MZHeader"
				$Regex = [Regex] "[\x20-\x7E]{$MinStringSize,}"
				$Regex.Matches($UTF8Strings) | % { 
					$Strings += $_.Value
				}
				$Regex.Matches($UnicodeStrings) | % { 
					$Strings += $_.Value
				}
				

				$Allocation | Add-Member -type NoteProperty -Name ProcessId -Value $ProcessID -Force
				$Allocation | Add-Member -type NoteProperty -Name ProcessName -Value $ProcessName -Force
				#$Allocation | Add-Member -type NoteProperty -Name ModuleName -Value $ModuleName -Force
				$Allocation | Add-Member -type NoteProperty -Name PE -Value $PE -Force
				$Allocation | Add-Member -type NoteProperty -Name Strings -Value $Strings -Force
				
				Write-Output $Allocation
			}

			$Bytes = $null
        }
        
        $null = $Kernel32::CloseHandle($hProcess)
    }

    END {

	}
}

# TODO
function Get-InjectedModule {
	<#		
		Info on parsing PE Headers in memory (tl;dr it's a zoo)
		https://media.blackhat.com/bh-us-11/Vuksan/BH_US_11_VuksanPericin_PECOFF_Slides.pdf
		
		PE headers
		By default the PE header has read and execute attributes set. If DEP has been turned on the header has read only attributes.
		
		FileAlignment:
		Hardcoded to 0x200 of the PECOFF
		The alignment factor (in bytes) that is used to align the raw data of sections in the image file. 
		The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512.
		PE file validations
			• Headers
				• Disallow files which have headers outside the NtSizeOfHeaders
				• Disallow files which have too big NtSizeOfOptionalHeaders field value
				• Disallow files which have entry point outside the file
			• Sections
				• Disallow files with zero sections
			• Imports
				• String validation
				• Disallow table reuse and overlap
			• Exports
				• Disallow multiple entries with the same name
				• Disallow entries which have invalid function addresses
			• Relocations
				• Block files which utilize multiple relocations per address
			• TLS
				• Disallow files whose TLS callbacks are outside the image
	#>
}

function Get-Modules {
	Write-Verbose "Getting loaded Modules"

	$modules = Get-Process -ea 0 -Module | where { $_.FileName -notmatch "\.exe$" } | sort-object FileName -unique

	$ModuleList = @()
	foreach ($module in $modules) {
		
		$newModule = New-Object PSObject -Property @{	
			ModuleName	= $module.ModuleName
			PathName	= $module.FileName
			Company		= $module.Company
			Product		= $module.Product
			ProductVersion = $module.ProductVersion
			FileVersion = $module.FileVersion
			Description = $module.Description
			InternalName = $module.FileVersionInfo.InternalName
			OriginalFilename = $module.FileVersionInfo.OriginalFilename
			Language    = $module.FileVersionInfo.Language
		}
		
		if ($module.FileName) {
			# Get hashes and verify Signatures with Sigcheck
			$Signature = Invoke-Sigcheck $module.FileName -GetHashes | Select -Property * -ExcludeProperty Path
			$Signature.PSObject.Properties | Foreach-Object {
				$newModule | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -Force
			}
		}
		
		$ModuleList += $newModule
	}	
	return $ModuleList
} 

function Get-Drivers {
	Write-Verbose "Getting Drivers"
	# Get driver Information
	$drivers = Get-WmiObject Win32_SystemDriver #| Select Name, DisplayName, Description, PathName, State, Started, StartMode, ServiceType
	
	$driverList = @()
	foreach ($driver in $drivers) { 
	#	Write-Host "in FIRST foreach: " $proc.ProcessId | ft #debug
		$path = Get-ParsedSystemPath $driver.PathName
		#$hashes = $null
		#$hashes = Get-Hashes $path
        #$VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)

		$newDriver = New-Object PSObject -Property @{
			Name			= $driver.Name
			DisplayName		= $driver.DisplayName
			Description		= $driver.Description
			PathName		= $path
			State			= $driver.State
			Started			= $driver.Started
			StartMode		= $driver.StartMode
			ServiceType		= $driver.ServiceType
		}	
		
		if ($path) {
			# Get hashes and verify Signatures with Sigcheck
			$Signature = Invoke-Sigcheck $path -GetHashes | Select -Property * -ExcludeProperty Path
			$Signature.PSObject.Properties | Foreach-Object {
				$newDriver | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -Force
			}
		}

		$driverList += $newDriver;
	}

	return $driverList;
}

function Get-DisplayDNS {
	Write-Verbose "Getting recent DNS resolutions"
	$d = ipconfig /displaydns
	$displaydns = @()
	$i = 0
	while($i -lt $d.length) {
		$vals = -Split $d[$i]
		if($vals[0] -like "Record") {
			$vals = -Split $d[$i]
			$request = $vals[8]
			$i += 5
			$vals = -Split $d[$i]
			$type = $vals[0]
			if( $type -match "PTR" ) {
				$answer = $vals[8]
			} else {
				$answer = $vals[7]
			}
			$record = New-Object PSObject -Property @{
				Request = $request
				Answer = $answer
				RequestType = $type
			}
			#write-host $record
			$displaydns += $record
		}
		$i += 1
	}
		
	return $displaydns
}

function Get-Netstat {
	Write-Verbose "Getting Netstat"
	$netstat = @()
	
	# Run netstat for tcp and udp
	$netstat_tcp = &{netstat -ano -p tcp}  | select -skip 4
	$netstat_udp = &{netstat -ano -p udp} | select -skip 4
	
	# Process output into objects
	foreach ($line in $netstat_tcp) { 	
		$val = -Split $line
		$l = $val[1] -Split ":" 
		$r = $val[2] -Split ":" 		
		$netstat += new-Object PSObject -Property @{
			Protocol		= $val[0] 
			Src_Address		= $l[0]
			Src_Port 		= [int]$l[1]
			Dst_Address 	= $r[0] 
			Dst_Port 		= [int]$r[1] 
			State 			= $val[3] 
			ProcessId 		= [int]$val[4]
			ProcessName 	= [String](Get-Process -Id ([int]$val[4])).Name
		}			
	}
	foreach ($line in $netstat_udp) { 	
		$val = -Split $line
		$l = $val[1] -Split ":" 
		$netstat += new-Object PSObject -Property @{
			Protocol		= $val[0] 
			Src_Address		= $l[0]
			Src_Port 		= [int]$l[1]
			Dst_Address 	= $null
			Dst_Port 		= [int]$null 
			State 			= $null
			ProcessId 		= [int]$val[3]
			ProcessName 	= [String](Get-Process -Id ([int]$val[3])).Name
		}
	}
	return $netstat
}

function Get-OldestLogs {
    # Get oldest log.  A limited look back could be indicative of a log wipe (it's infinitely easier to delete all logs than manipulate individual ones - expect it)
	$Oldest = @()
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='Application'} | Select LogName,TimeCreated
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='Security'} | Select LogName,TimeCreated
	$Oldest +=  Get-WinEvent -Oldest -MaxEvents 1 -FilterHashTable @{LogName='System'} | Select LogName,TimeCreated
	return $Oldest
}

Function Get-PSAutorun {
<#
    .SYNOPSIS
        Get Autorun entries.
		
		Author: Emin Atac
		Updated by: Chris Gerritz (Github @singlethreaded) (Twitter @gerritzc)
		License: BSD 3-clause 
		Required Dependencies: None
		Optional Dependencies: None
     
    .DESCRIPTION
        Retrieve a list of programs configured to autostart at boot or logon.
      
    .PARAMETER All
        Switch to gather artifacts from all categories. 
        If it's turned on, all other category switches will be ignored.
      
    .PARAMETER BootExecute
        Switch to gather artifacts from the Boot Execute category.

    .PARAMETER AppinitDLLs
        Switch to gather artifacts from the Appinit category.
    
    .PARAMETER ExplorerAddons
        Switch to gather artifacts from the Explorer category.

    .PARAMETER SidebarGadgets
        Switch to gather artifacts from the Sidebar Gadgets category.

    .PARAMETER ImageHijacks
        Switch to gather artifacts from the Image Hijacks category.

    .PARAMETER InternetExplorerAddons
        Switch to gather artifacts from the Intenet Explorer category.

    .PARAMETER KnownDLLs
        Switch to gather artifacts from the KnownDLLs category.

    .PARAMETER Logon
        Switch to gather artifacts from the Logon category.

    .PARAMETER Winsock
        Switch to gather artifacts from the Winsock and network providers category.

    .PARAMETER Codecs
        Switch to gather artifacts from the Codecs category.

    .PARAMETER OfficeAddins
        Switch to gather artifacts from Office Addins

    .PARAMETER PrintMonitorDLLs
        Switch to gather artifacts from the Print Monitors category.

    .PARAMETER LSAsecurityProviders
        Switch to gather artifacts from the LSA Providers category.

    .PARAMETER ServicesAndDrivers
        Switch to gather artifacts from the Services and Drivers categories.

    .PARAMETER ScheduledTasks
        Switch to gather artifacts from the Scheduled tasks category.

    .PARAMETER Winlogon
        Switch to gather artifacts from the Winlogon category.

    .PARAMETER WMI
        Switch to gather artifacts from the WMI category.

    .PARAMETER ShowFileHash
        Switch to enable and display MD5, SHA1 and SHA2 file hashes.

    .PARAMETER VerifyDigitalSignature
        Switch to report if a file is digitally signed with the built-in Get-AuthenticodeSignature cmdlet.
              
    .EXAMPLE
        Get-PSAutorun -BootExecute -AppinitDLLs

    .EXAMPLE
        Get-PSAutorun -KnownDLLs -LSAsecurityProviders -ShowFileHash

    .EXAMPLE
         Get-PSAutorun -All -ShowFileHash -VerifyDigitalSignature

#>
    [CmdletBinding()]
    Param(
        [switch]$All,
        [Switch]$BootExecute,
        [Switch]$AppinitDLLs,
        [Switch]$ExplorerAddons,
        [Switch]$SidebarGadgets,
        [Switch]$ImageHijacks,
        [Switch]$InternetExplorerAddons,
        [Switch]$KnownDLLs,
        [Switch]$Logon,
        [Switch]$Winsock,
        [Switch]$Codecs,
        [Switch]$OfficeAddins,
        [Switch]$PrintMonitorDLLs,
        [Switch]$LSAsecurityProviders,
        [Switch]$ServicesAndDrivers,
        [Switch]$ScheduledTasks,
        [Switch]$Winlogon,
        [Switch]$WMI,
        [Switch]$ShowFileHash,
		[Switch]$CheckSignatures
    )

Begin {
    #region Helperfunctions

    # Courtesy of Microsoft
    # Extracted from PS 4.0 with (dir function:\Get-FileHash).Definition
	Function Get-FileHash {
		[CmdletBinding(DefaultParameterSetName = 'Path')]
		Param(
			[Parameter(Mandatory=$true, ParameterSetName='Path', Position = 0)]
			[System.String[]]
			$Path,

			[Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName = $true)]
			[Alias('PSPath')]
			[System.String[]]
			$LiteralPath,
		
			[ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'MD5', 'RIPEMD160')]
			[System.String]
			$Algorithm='SHA256'
		)

		Begin {
			# Construct the strongly-typed crypto object
			try { 
				$hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
			} catch {
				Write-Warning "ERROR: Could not create hashing algorithm: $Algorithm"
			}
			
		}
		Process {
			$pathsToProcess = @()
			
			if($PSCmdlet.ParameterSetName  -eq 'LiteralPath') {
				$pathsToProcess += Resolve-Path -LiteralPath $LiteralPath | Foreach-Object { $_.ProviderPath }
			} else {
				$pathsToProcess += Resolve-Path $Path | Foreach-Object { $_.ProviderPath }
			}
				
			foreach($filePath in $pathsToProcess) {
				if ($hasher) {
					if(Test-Path -LiteralPath $filePath -PathType Container) {
						continue
					}
				
					try {
						# Read the file specified in $FilePath as a Byte array
						[system.io.stream]$stream = [system.io.file]::OpenRead($FilePath)
					
						# Compute file-hash using the crypto object
						[Byte[]] $computedHash = $hasher.ComputeHash($stream)
					} catch [Exception] {
						Write-Error -Message $_ -Category ReadError -ErrorId 'FileReadError' -TargetObject $FilePath
						return
					} finally {
						if($stream) {
							$stream.Close()
						}
					}
							
					# Convert to hex-encoded string
					[string] $hash = [BitConverter]::ToString($computedHash) -replace '-',''
					
					$retVal = New-Object -Type PSCustomObject -Property @{
						Algorithm = $Algorithm.ToUpperInvariant()
						Hash = $hash
						Path = $filePath
					}
					$retVal.psobject.TypeNames.Insert(0, 'Microsoft.Powershell.Utility.FileHash')
					$retVal
				} else {
					$retVal = New-Object -Type PSCustomObject -Property @{
						Algorithm = $Algorithm.ToUpperInvariant()
						Hash = $null
						Path = $filePath
					}
					$retVal.psobject.TypeNames.Insert(0, 'Microsoft.Powershell.Utility.FileHash')
					$retVal		
				}
			}
		}
	}

    Function Get-RegValue {
    [CmdletBinding()]
    Param(
        [string]$Path,
        [string[]]$Name,
        [string]$Category
    )
    Begin{
        if ($Path -match 'Wow6432Node') {
            $ClassesPath = Join-Path -Path (Split-Path $Path -Qualifier) -ChildPath 'SOFTWARE\Wow6432Node\Classes\CLSID'
        } else {
            $ClassesPath = Join-Path -Path (Split-Path $Path -Qualifier) -ChildPath 'SOFTWARE\Classes\CLSID'
        }
    }
    Process {
        try {
            $Values = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($Name -eq '*') {
                $Name = $Values.GetValueNames()
            }
            $Name | ForEach-Object -Process {
                # Need to differentiate between empty string and really non existing values
                if ($null -ne $Values.GetValue($_)) {
                    $Value  = Switch -regex($Values.GetValue($_)) {
                        '^\{[A-Z0-9]{4}([A-Z0-9]{4}-){4}[A-Z0-9]{12}\}$' {
                            (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            break
                        }
                        default {
                            $_ 
                        }
                    }
                    if ($Value) {
						$Result = New-Object -TypeName pscustomobject -Property @{
                            Path = $Path
                            Item = $_
                            Value = $Value
                            Category = $Category
                        }
						Write-Output $Result
                    }
                }
            }
        } catch {
        }
    }
    End {}
    }

    Function Get-AllScheduledTask {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
            [System.String[]]$ComputerName = "localhost"
        )
        Begin {
            Function Get-SubFolder ($folder,[switch]$recurse) {
                $folder
                if ($recurse) {
                    $TaskService.GetFolder($folder).GetFolders(0) | ForEach-Object {
                    Get-SubFolder $_.Path -Recurse
                    }
                } else {
                    $TaskService.GetFolder($folder).GetFolders(0)
                }
   
            }
        }
        Process {
            $ComputerName | ForEach-Object -Process {
                $alltasks = @()
                $Computer  = $_
                try {
					# This won't work on Win2k3 (schedule.service com object does not exist)
					$TaskService = New-Object -com schedule.service
                    $null = $TaskService.Connect($Computer)
                } catch {
                    Write-Warning "Cannot connect to $Computer TaskScheduler because $($_.Exception.Message)"
                    return
                }
                $tasks = Get-SubFolder -folder '\' -recurse | ForEach-Object -Process {

                    $TaskService.GetFolder($_).GetTasks(1) }
				$tasks | foreach-object {
					[xml]$txml = $_.xml
					$obj = New-Object -TypeName pscustomobject -Property @{
						ComputerName = $env:COMPUTERNAME
						Path = Split-Path $_.Path
						Name = $_.Name
						ImagePath = [System.Environment]::ExpandEnvironmentVariables($txml.Task.Actions.Exec.command)
						TaskArgs = $txml.Task.Actions.Exec.Arguments
					}
					$alltasks += $obj
				}
                Write-Verbose -Message "There's a total of $($alltasks.Count) tasks on $Computer"
                $alltasks | Add-Sigcheck -CheckSignatures
            }
        }
        End {}
    }

    Function Get-Task {
    [CmdletBinding()]
    [OutputType('System.Object[]')]
        param (
        [parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,Mandatory=$false)]
        [system.string[]] ${ComputerName} = $env:computername,

        [parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,Mandatory=$false,
                    HelpMessage="The task folder string must begin by '\'")]
        [ValidatePattern('^\\')]
        [system.string[]] ${Path} = '\',

        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [system.string[]] ${Name} = $null
        )
        Begin {}
        Process
        {
            $resultsar = @()
            $ComputerName | ForEach-Object -Process {
                $Computer = $_
                try {
					# This won't work on Win2k3 (schedule.service com object does not exist)
					$TaskService = New-Object -com schedule.service
                    $null = $TaskService.Connect($Computer)
                } catch {
                    Write-Warning "Cannot connect to $Computer TaskScheduler because $($_.Exception.Message)"
                    return
                }
                if ($TaskService.Connected) {
                    Write-Verbose -Message "Connected to the scheduler service of computer $Computer"
                        Foreach ($Folder in $Path) {
                            Write-Verbose -Message "Dealing with folder task $Folder"
                            $RootFolder = $null
                            try {
                                $RootFolder = $TaskService.GetFolder($Folder)
                            } catch {
                                Write-Warning -Message "The folder task $Folder cannot be found"
                            }
                            if ($RootFolder) {
                                Foreach ($Task in $Name) {
                                    $TaskObject = $null
                                    try {
                                        Write-Verbose -Message "Dealing with task name $Task"
                                        $TaskObject = $RootFolder.GetTask($Task)
                                    } catch {
                                        Write-Warning -Message "The task $Task cannot be found under $Folder"
                                    }
                                    if ($TaskObject) {
                                        # Status
                                        # http://msdn.microsoft.com/en-us/library/windows/desktop/aa383617%28v=vs.85%29.aspx
                                        switch ($TaskObject.State) {
                                            0 { $State = 'Unknown'  ; break}
                                            1 { $State = 'Disabled' ; break}
                                            2 { $State = 'Queued'   ; break}
                                            3 { $State = 'Ready'    ; break}
                                            4 { $State = 'Running'  ; break}
                                            default {$State = $_ }
                                        }

                                        $resultsar += New-Object -TypeName pscustomobject -Property @{
                                            ComputerName = $Computer
                                            Name = $TaskObject.Name
                                            Path = $Folder
                                            State = $State
                                            Enabled = $TaskObject.Enabled
                                            Xml = $TaskObject.XML

                                        }
                                    }
                                }
                            }
                        }
                }
            }
            $resultsar
        } 
        End {}
    }

    # From David Wyatt
    # http://gallery.technet.microsoft.com/scriptcenter/Normalize-file-system-5d33985a
    Function Get-NormalizedFileSystemPath {
        <#
        .Synopsis
            Normalizes file system paths.
        .DESCRIPTION
            Normalizes file system paths.  This is similar to what the Resolve-Path cmdlet does, except Get-NormalizedFileSystemPath also properly handles UNC paths and converts 8.3 short names to long paths.
        .PARAMETER Path
            The path or paths to be normalized.
        .PARAMETER IncludeProviderPrefix
            If this switch is passed, normalized paths will be prefixed with 'FileSystem::'.  This allows them to be reliably passed to cmdlets such as Get-Content, Get-Item, etc, regardless of Powershell's current location.
        .EXAMPLE
            Get-NormalizedFileSystemPath -Path '\\server\share\.\SomeFolder\..\SomeOtherFolder\File.txt'

            Returns '\\server\share\SomeOtherFolder\File.txt'
        .EXAMPLE
            '\\server\c$\.\SomeFolder\..\PROGRA~1' | Get-NormalizedFileSystemPath -IncludeProviderPrefix

            Assuming you can access the c$ share on \\server, and PROGRA~1 is the short name for "Program Files" (which is common), returns:

            'FileSystem::\\server\c$\Program Files'
        .INPUTS
            String
        .OUTPUTS
            String
        .NOTES
            Paths passed to this command cannot contain wildcards; these will be treated as invalid characters by the .NET Framework classes which do the work of validating and normalizing the path.
        .LINK
            Resolve-Path
        #>

        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [Alias('PSPath', 'FullName')]
            [string[]]
            $Path,

            [switch]
            $IncludeProviderPrefix
        )
        Process{
            foreach ($_path in $Path)
            {
                $_resolved = $_path

                if ($_resolved -match '^([^:]+)::') {
                    $providerName = $matches[1]

                    if ($providerName -ne 'FileSystem') {
                        Write-Error "Only FileSystem paths may be passed to Get-NormalizedFileSystemPath.  Value '$_path' is for provider '$providerName'."
                        continue
                    }

                    $_resolved = $_resolved.Substring($matches[0].Length)
                }

                if (-not [System.IO.Path]::IsPathRooted($_resolved)) {
                    $_resolved = Join-Path -Path $PSCmdlet.SessionState.Path.CurrentFileSystemLocation -ChildPath $_resolved
                }

                try {
                    $dirInfo = New-Object System.IO.DirectoryInfo($_resolved)
                } catch {
                    $exception = $_.Exception
                    while ($null -ne $exception.InnerException) {
                        $exception = $exception.InnerException
                    }
                    Write-Error "Value '$_path' could not be parsed as a FileSystem path: $($exception.Message)"
                    continue
                }
    
                $_resolved = $dirInfo.FullName

                if ($IncludeProviderPrefix) {
                    $_resolved = "FileSystem::$_resolved"
                }
                Write-Output $_resolved
            }
        } 
    }
    
    Function Get-PSRawAutoRun {
        [CmdletBinding()]
        Param(
            [switch]$All,
            [Switch]$BootExecute,
            [Switch]$AppinitDLLs,
            [Switch]$ExplorerAddons,
            [Switch]$SidebarGadgets,
            [Switch]$ImageHijacks,
            [Switch]$InternetExplorerAddons,
            [Switch]$KnownDLLs,
            [Switch]$Logon,
            [Switch]$Winsock,
            [Switch]$Codecs,
            [Switch]$OfficeAddins,
            [Switch]$PrintMonitorDLLs,
            [Switch]$LSAsecurityProviders,
            [Switch]$ServicesAndDrivers,
            [Switch]$ScheduledTasks,
            [Switch]$Winlogon,
            [Switch]$WMI,
            [Switch]$ShowFileHash,
			[Switch]$CheckSignatures
        )
        Begin {
        }
        Process {
            if ($All -or $BootExecute) {
                Write-Verbose -Message 'Looking for Boot Execute entries'
                #region Boot Execute
	            $Category = @{ Category = 'Boot Execute'}

                # REG_MULTI_SZ
	            'BootExecute','SetupExecute','Execute','S0InitialCommand' | ForEach-Object {
		            $item = $_
                    $v = $null
                    $v = (Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name $_ @Category)
                    if ($v) {
                        $v.Value | ForEach-Object {
                            if ($_ -ne '""') {
                                New-Object -Type pscustomobject -Property @{
                                    Path = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
                                    Item = $item
                                    Value = $_
                                    Category = 'Boot Execute'
                                }
                            }
                        }
                    }
	            }

	            Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control' -Name 'ServiceControlManagerExtension' @Category
                #endregion Boot Execute
            }
            if ($All -or $AppinitDLLs) {
                Write-Verbose -Message 'Looking for Appinit DLLs entries'
                #region AppInit
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows NT\CurrentVersion\Windows" -Name 'Appinit_Dlls' -Category 'AppInit'
	            }

	            if (Test-Path -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' -PathType Container) {
		            Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' -Name '*' -Category 'AppInit'
	            }
                #endregion AppInit
            }
            if ($All -or $ExplorerAddons) {
                Write-Verbose -Message 'Looking for Explorer Add-ons entries'
                #region Explorer
    
                $Category = @{ Category = 'Explorer'}

                # Filter & Handler
                'Filter','Handler' | ForEach-Object -Process {
                    $key = "HKLM:\SOFTWARE\Classes\Protocols\$($_)"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            if ($_ -eq 'ms-help') {
                                if ([environment]::Is64BitOperatingSystem) {
                                    $ClassesPath = 'HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID'
                                } else {
                                    $ClassesPath = 'HKLM:\SOFTWARE\Classes\CLSID'
                                }
                                $i = (Get-ItemProperty -Path "$key\ms-help" -Name 'CLSID').CLSID
                                New-Object -Type pscustomobject -Property @{
                                    Path = "$key\ms-help"
                                    Item = $i
                                    Value = $(
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID' -ChildPath "$($i)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($i)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                    ) | Where-Object { $null -ne $_ } | Sort-Object -Unique
                                    Category = 'Explorer'
                                }
                            } else {
                                Get-RegValue -Path "$key\$($_)" -Name 'CLSID' @Category
                            }
                        }
                    }
                }

                # SharedTaskScheduler
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" -Name '*' @Category
                }

                # ShellServiceObjects
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = $(
                                try {
                                    (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
                                } catch {
                                    $null
                                }
                            )
                            Category = 'Explorer'
                        }
                    }
                }

                # ShellExecuteHooks
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
                    if (Test-Path -Path $key -PathType Container) {
                        $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                         (Get-Item -Path $key).GetValueNames() | ForEach-Object {
                            # Get-RegValue -Path $key -Name $_ @Category
                            New-Object -Type pscustomobject -Property @{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Explorer'
                            }
                         }
                    }
                }
    
                # ShellServiceObjectDelayLoad
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" -Name '*' @Category
                }

                # Handlers
                @(
                    @{Name = '*' ; Properties = @('ContextMenuHandlers','PropertySheetHandlers')},
                    @{Name ='Drive'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='AllFileSystemObjects'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers')},
                    @{Name ='Directory'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers', 'CopyHookHandlers')},
                    @{Name ='Directory\Background'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='Folder' ; Properties = @('ColumnHandlers','ContextMenuHandlers','DragDropHandlers','ExtShellFolderViews','PropertySheetHandlers')}
                ) | ForEach-Object -Process {
        
                    $Name = $_.Name
                    $Properties = $_.Properties

                    $null,'Wow6432Node' | Foreach-Object -Process { 
                        $key = "HKLM:\Software\$($_)\Classes\$Name\ShellEx"
                        $ClassPath = "HKLM:\Software\$($_)\Classes\CLSID"
                        $Hive = $_
                        $Properties | ForEach-Object -Process {
                            $subkey = Join-Path -Path $key -ChildPath $_
                            try {
                                (Get-Item -LiteralPath $subkey -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                                    if ($(try {
                                        [system.guid]::Parse($_) | Out-Null
                                        $true
                                    } catch {
                                        $false
                                    })) {
                                        if (Test-Path -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -PathType Container) {
                                            # don't change anything
                                        } else {
                                            if ($Hive) {
                                                $ClassPath = 'HKLM:\Software\Classes\CLSID'
                                            } else {
                                                $ClassPath = 'HKLM:\Software\Wow6432Node\Classes\CLSID'
                                            }
                                        }
                                        if (Test-PAth -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -PathType Container) {
                                            New-Object -Type pscustomobject -Property @{
                                                Path = $key
                                                Item = $_
                                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                                Category = 'Explorer'
                                            }
                                        }
                                    } else {
                                        Get-RegValue -Path "$subkey\$($_)" -Name '*' @Category
                                    }
                                }
                             } catch {
                             }
                        }
                    }
                } 

                # ShellIconOverlayIdentifiers
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                        }
                    }
                }

                # LangBarAddin
                Get-RegValue -Path 'HKLM:\Software\Microsoft\Ctf\LangBarAddin' -Name '*' @Category

                #endregion Explorer

                #region User Explorer

                # Filter & Handler
                'Filter','Handler' | ForEach-Object -Process {
                    $key = "HKCU:\SOFTWARE\Classes\Protocols\$($_)"
                    if (Test-Path -Path $key  -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path "$key\$($_)" -Name 'CLSID' @Category
                        }
                    }
                }   

                if (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Desktop\Components' -PathType Container) {
                    $key = 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Desktop\Components'
	                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
			                Get-RegValue -Path "$key\$($_)" -Name 'Source' @Category
	                }
                }

                # ShellServiceObjects
                if (Test-Path -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects' -PathType Container) {
                    $ClassesPath =  "HKCU:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                            Category = 'Explorer'
                        }
                    }
                }
    
                # ShellServiceObjectDelayLoad
                Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad' -Name '*' @Category

                # Handlers
                @(
                    @{Name = '*' ; Properties = @('ContextMenuHandlers','PropertySheetHandlers')},
                    @{Name ='Drive'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='AllFileSystemObjects'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers')},
                    @{Name ='Directory'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers', 'CopyHookHandlers')},
                    @{Name ='Directory\Background'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='Folder' ; Properties = @('ColumnHandlers','ContextMenuHandlers','DragDropHandlers','ExtShellFolderViews','PropertySheetHandlers')}
                ) | ForEach-Object -Process {
        
                    $Name = $_.Name
                    $Properties = $_.Properties

                    $key = "HKCU:\Software\Classes\$Name\ShellEx"
                    $Properties | ForEach-Object -Process {
                        $subkey = Join-Path -Path $key -ChildPath $_
                        try {
                            (Get-Item -LiteralPath $subkey -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path "$subkey\$($_)" -Name '*' @Category
                            }
                        } catch {
                        }
                    }
                }

                # ShellIconOverlayIdentifiers
                $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                    }
                }

                # LangBarAddin
                Get-RegValue -Path 'HKCU:\Software\Microsoft\Ctf\LangBarAddin' -Name '*' @Category

                # NEW! POWELIKS use of Window's thumbnail cache
                if (Test-Path -Path 'HKCU:\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}') {
                    Write-Warning -Message 'Infected by PoweLiks malware'
                    # Step1: restore read access
                    try {
                        $ParentACL = Get-Acl -Path 'HKCU:\Software\Classes\Clsid'
                        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}','ReadWriteSubTree','TakeOwnership')
                        $acl  = $k.GetAccessControl()
                        $acl.SetAccessRuleProtection($false,$true)
                        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($ParentACL.Owner,'FullControl','Allow')
                        $acl.SetAccessRule($rule)
                        $k.SetAccessControl($acl)
                        Write-Verbose -Message "Successuflly restored read access for $($ParentACL.Owner) on registry key"
                    } catch {
                        Write-Warning -Message "Failed to restore read access for $($ParentACL.Owner) on registry key"
                    }
                    # Step2: read the content of subkeys
                    'Inprocserver32','localserver32' | ForEach-Object {
                        try {
                            (Get-ItemProperty -Path "HKCU:\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\$($_)" -Name '(default)' -ErrorAction Stop).'(default)'
                        } catch {
                        }
                    }
                }
                #endregion User Explorer
            }
            if ($All -or $SidebarGadgets) {
                Write-Verbose -Message 'Looking for Sidebar gadgets'
                #region User Sidebar gadgets

                if (Test-Path (Join-Path -Path (Split-Path -Path $($env:AppData) -Parent) -ChildPath 'Local\Microsoft\Windows Sidebar\Settings.ini')) {

                    Get-Content -Path (
                        Join-Path -Path (Split-Path -Path $($env:AppData) -Parent) -ChildPath 'Local\Microsoft\Windows Sidebar\Settings.ini'
                    ) | 
                    Select-String -Pattern '^PrivateSetting_GadgetName=' | ForEach-Object {

                            New-Object -Type pscustomobject -Property @{
                                Path = Join-Path -Path (Split-Path -Path $($env:AppData) -Parent) -ChildPath 'Local\Microsoft\Windows Sidebar\Settings.ini'
                                Item = [string]::Empty
                                Value = ($_.Line -split '=' | Select-Object -Last 1) -replace '%5C','\' -replace '%20',' '
                                Category = 'SideBar Gadgets'
                            }
                     }
                }
                #endregion User Sidebar gadgets
            }
            if ($All -or $ImageHijacks) {
                Write-Verbose -Message 'Looking for Image hijacks'
                #region Image Hijacks
	            $Category = @{ Category = 'Image Hijacks'}
                $null,'Wow6432Node' | Foreach-Object {
		            $key = "HKLM:\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
			            Get-RegValue -Path "$key\$($_)" -Name 'Debugger' @Category
		            }
	            }		

                # Autorun macro	
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\Software\$($_)\Microsoft\Command Processor" -Name 'Autorun' @Category		
	            }
	
                # Exefile
                New-Object -Type pscustomobject -Property @{
                    Path = 'HKLM:\SOFTWARE\Classes\Exefile\Shell\Open\Command'
                    Item = 'exefile'
                    Value = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Exefile\Shell\Open\Command' -Name '(default)').'(default)'
                    Category = 'Image Hijacks'
                }
	
	            '.exe','.cmd' | Foreach-Object {
		            $assoc = (Get-ItemProperty -Path "HKLM:\Software\Classes\$($_)" -Name '(default)').'(default)'
                    New-Object -Type pscustomobject -Property @{
                        Path = "HKLM:\Software\Classes\$assoc\shell\open\command"
                        Item = $_ 
                        Value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$assoc\Shell\Open\Command" -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
	            }

                # Htmlfile
                New-Object -Type pscustomobject -Property @{
                    Path = 'HKLM:\SOFTWARE\Classes\htmlfile\shell\open\command'
                    Item = 'htmlfile'
                    Value = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\htmlfile\shell\open\command' -Name '(default)').'(default)'
                    Category = 'Image Hijacks'
                }
                #endregion Image Hijacks

                #region User Image Hijacks

                Get-RegValue -Path 'HKCU:\Software\Microsoft\Command Processor' -Name 'Autorun' @Category		
	
                # Exefile
                if (Test-Path -Path 'HKCU:\SOFTWARE\Classes\Exefile\Shell\Open\Command') {
                    New-Object -Type pscustomobject -Property @{
                        Path = 'HKCU:\SOFTWARE\Classes\Exefile\Shell\Open\Command'
                        Item = 'exefile'
                        Value = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\Exefile\Shell\Open\Command' -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
                }
	
	            '.exe','.cmd' | Foreach-Object {
                    if (Test-Path -Path "HKCU:\Software\Classes\$($_)") {
		                $assoc = (Get-ItemProperty -Path "HKCU:\Software\Classes\$($_)" -Name '(default)'-ErrorAction SilentlyContinue).'(default)'
                        if ($assoc) {
                            New-Object -Type pscustomobject -Property @{
                                Path = "HKCU:\Software\Classes\$assoc\shell\open\command"
                                Item = $_ 
                                Value = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Classes\$assoc\Shell\Open\Command" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                Category = 'Image Hijacks'
                            }
                        }
                    }
	            }

                # Htmlfile
                if (Test-Path -Path 'HKCU:\SOFTWARE\Classes\htmlfile\shell\open\command') {
                    New-Object -Type pscustomobject -Property @{
                        Path = 'HKCU:\SOFTWARE\Classes\htmlfile\shell\open\command'
                        Item = 'htmlfile'
                        Value = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Classes\htmlfile\shell\open\command' -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
                }
                #endregion User Image Hijacks
            }
            if ($All -or $InternetExplorerAddons) {
                Write-Verbose -Message 'Looking for Internet Explorer Add-ons entries'
                #region Internet Explorer

                $Category = @{ Category = 'Internet Explorer'}
    
                # Browser Helper Objects
                $null,'Wow6432Node' | Foreach-Object {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            New-Object -Type pscustomobject -Property @{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    }
                }

                # IE Toolbars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Toolbar" -Name '*' @Category
                }

                # Explorer Bars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Explorer Bars"
                    try {
                        (Get-Item -Path $key -ErrorAction Stop).GetSubKeyNames() | ForEach-Object -Process {
                            New-Object -Type pscustomobject -Property @{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    } catch {
                    }
                }

                # IE Extensions
                $null,'Wow6432Node' | Foreach-Object {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Extensions"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name 'ClsidExtension' @Category
                        }
                    }
                }

                #endregion Internet Explorer

                #region User Internet Explorer

                # UrlSearchHooks
                $ClassesPath =  'HKLM:\SOFTWARE\Classes\CLSID'
                $key = 'HKCU:\Software\Microsoft\Internet Explorer\UrlSearchHooks'
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetValueNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                            Category = 'Internet Explorer'
                        }
                    }
                }

                # Explorer Bars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKCU:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Explorer Bars"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            New-Object -Type pscustomobject -Property @{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    }
                }

                # IE Extensions
                $null,'Wow6432Node' | Foreach-Object {
                    $key = "HKCU:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Extensions"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name 'ClsidExtension' @Category
                        }
                    }
                }

                #endregion User Internet Explorer
            }
            if ($All -or $KnownDLLs) {
                Write-Verbose -Message 'Looking for Known DLLs entries'
                #region Known Dlls
	            Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -Name '*' -Category 'Known Dlls'
                #endregion Known Dlls
            }
            if ($All -or $Logon) {
                Write-Verbose -Message 'Looking for Logon Startup entries'
                #region Logon

                $Category = @{ Category = 'Logon'}

                # Winlogon
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'VmApplet','Userinit','Shell','TaskMan','AppSetup' @Category

                # GPExtensions
	            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'
                if (Test-Path -Path $key -PathType Container) {
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        try {
                            New-Object -Type pscustomobject -Property @{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $key -ChildPath $_) -Name 'DllName' -ErrorAction Stop).'DllName'
                                Category = 'Logon'
                            }
                        } catch {}			
		            }			
	            }
    
                # Domain Group Policies scripts
                'Startup','Shutdown','Logon','Logoff' | ForEach-Object -Process {
                    $key = "HKLM:\Software\Policies\Microsoft\Windows\System\Scripts\$($_)"
                    if (Test-Path -Path $key) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            $subkey = (Join-Path -Path $key -ChildPath $_)
                            (Get-Item -Path $subkey).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category 
                            }
                        }
                    }
                }    

                # Local GPO scripts
                'Startup','Shutdown' | ForEach-Object -Process {
                    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$($_)"
                    if (Test-Path -Path $key) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            $subkey = (Join-Path -Path $key -ChildPath $_)
                            (Get-Item -Path $subkey).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category 
                            }
                        }
                    }
                }    

                # Shell override by GPO
                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'Shell' @Category

                # AlternateShell
                Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell' @Category

                # AvailableShells
                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells' -Name 'AvailableShells' @Category

                # Terminal server
                Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd' -Name 'StartupPrograms' @Category
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce' -Name '*' @Category
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx' -Name '*' @Category
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run' -Name '*' @Category
                Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'  -Name 'InitialProgram' @Category

                # Run
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Run" -Name '*' @Category }

                # RunOnce
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnce" -Name '*' @Category }

                # RunOnceEx
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx" -Name '*' @Category }

                # LNK files or direct executable
                if (Test-Path -Path "$($env:systemdrive)\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -PathType Container) {
                    $Wsh = new-object -comobject 'WScript.Shell'
                    Get-ChildItem -Path "$($env:systemdrive)\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" |ForEach-Object {
                        $File = $_
                        $header = (Get-Content -Path $($_.FullName) -Encoding Byte -ReadCount 1 -TotalCount 2) -as [string]
                        Switch ($header) {
                            '77 90' {
                                New-Object -Type pscustomobject -Property @{
                                    Path = "$($env:systemdrive)\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                                    Item = $File.Name
                                    Value = $File.FullName
                                    Category = 'Logon'
                                }
                                break
                            }
                            '76 0' {
                                $shortcut = $Wsh.CreateShortcut($File.FullName)
                                New-Object -Type pscustomobject -Property @{
                                    Path = "$($env:systemdrive)\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
                                    Item = $File.Name
                                    Value = "$($shortcut.TargetPath) $($shortcut.Arguments)"
                                    Category = 'Logon'
                                }
                                break

                            }
                            default {}
                        }
                    }
                }

                # Run by GPO
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' -Name '*' @Category

                # Show all subkey that have a StubPath value
                $null,'Wow6432Node' | Foreach-Object { 
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Active Setup\Installed Components"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name 'StubPath' @Category
                    }

                }

                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'IconServiceLib' @Category

                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows CE Services\AutoStartOnConnect" -Name '*' @Category }
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows CE Services\AutoStartOnDisconnect" -Name '*' @Category }

                #endregion Logon

                #region User Logon

                # Local GPO scripts
                'Logon','Logoff' | ForEach-Object -Process {
                    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$($_)"
                    if (Test-Path -Path $key) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            $subkey = (Join-Path -Path $key -ChildPath $_)
                            (Get-Item -Path $subkey).GetSubKeyNames() | ForEach-Object -Process {
                                # (Join-Path -Path $subkey -ChildPath $_)
                                Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category 
                            }

                        }
                    }
                }

                # Shell override by GPO
                Get-RegValue -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'Shell' @Category

                # LNK files or direct executable
                if (Test-Path -Path "$($env:AppData)\Microsoft\Windows\Start Menu\Programs\Startup") {
                    $Wsh = new-object -comobject 'WScript.Shell'
                    Get-ChildItem -Path "$($env:AppData)\Microsoft\Windows\Start Menu\Programs\Startup" |ForEach-Object {
                        $File = $_
                        $header = (Get-Content -Path $($_.FullName) -Encoding Byte -ReadCount 1 -TotalCount 2) -as [string]
                        Switch ($header) {
                            '77 90' {
                                New-Object -Type pscustomobject -Property @{
                                    Path = "$($env:AppData)\Microsoft\Windows\Start Menu\Programs\Startup"
                                    Item = $File.Name
                                    Value = $File.FullName
                                    Category = 'Logon'
                                }
                                break
                            }
                            '76 0' {
                                $shortcut = $Wsh.CreateShortcut($File.FullName)
                                New-Object -Type pscustomobject -Property @{
                                    Path = "$($env:AppData)\Microsoft\Windows\Start Menu\Programs\Startup"
                                    Item = $File.Name
                                    Value = "$($shortcut.TargetPath) $($shortcut.Arguments)"
                                    Category = 'Logon'
                                }
                                break

                            }
                            default {}
                        }
                    }
                }
    
                Get-RegValue -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'Load' @Category
                Get-RegValue -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'Run' @Category

                # Run by GPO
                Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' -Name '*' @Category
    
                # Run
                $null,'Wow6432Node' | ForEach-Object {
                    Get-RegValue -Path "HKCU:\Software\$($_)\Microsoft\Windows\CurrentVersion\Run" -Name '*' @Category 
                }

                # RunOnce
                $null,'Wow6432Node' | ForEach-Object {
                    Get-RegValue -Path "HKCU:\Software\$($_)\Microsoft\Windows\CurrentVersion\RunOnce" -Name '*' @Category 
                }

                # RunOnceEx
                $null,'Wow6432Node' | ForEach-Object {
                    Get-RegValue -Path "HKCU:\Software\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx" -Name '*' @Category 
                }

                Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce' -Name '*' @Category
                Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx' -Name '*' @Category
                Get-RegValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run' -Name '*' @Category

                #endregion User Logon

            }
            if ($All -or $Winsock) {
                Write-Verbose -Message 'Looking for Winsock protocol and network providers entries'
                #region Winsock providers

                $Category = @{ Category = 'Winsock Providers'}

                $null,'64' | ForEach-Object -Process {
                    $key = "HKLM:\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries$($_)"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = "$key\$($_)"
                            Item = 'PackedCatalogItem'
                            Value = ((New-Object -TypeName System.Text.ASCIIEncoding).GetString(
                                (Get-ItemProperty -Path "$key\$($_)" -Name PackedCatalogItem).PackedCatalogItem,0,211
                            ) -split ([char][int]0))[0]
                            Category = 'Winsock Providers'
                        }
                    }
                }

                $null,'64' | ForEach-Object -Process {
                    $key = "HKLM:\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries$($_)"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name 'LibraryPath' @Category
                    }
                }
                #endregion Winsock providers

                #region Network providers
	            $Category = @{ Category = 'Network Providers'}
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
	            (Get-RegValue -Path $key -Name 'ProviderOrder' @Category).Value -split ',' | ForEach-Object {
		            Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\$($_)\NetworkProvider" -Name 'ProviderPath' @Category
	            }
                #endregion Network providers
            }
            if ($All -or $Codecs) {
                Write-Verbose -Message 'Looking for Codecs'
                #region Codecs
	            $Category = @{ Category = 'Codecs'}

                # Drivers32
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name '*' @Category
	            }		

                # Filter
	            $key = 'HKLM:\Software\Classes\Filter'
                if (Test-Path -Path $key -PathType Container) {
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            Category = 'Codecs'
                        }			
		            }			
	            }

                # Instances
	            @('{083863F1-70DE-11d0-BD40-00A0C911CE86}','{AC757296-3522-4E11-9862-C17BE5A1767E}',
	            '{7ED96837-96F0-4812-B211-F13C24117ED3}','{ABE3B9A4-257D-4B97-BD1A-294AF496222E}') | Foreach-Object -Process {
		            $Item = $_
		            $null,'Wow6432Node' | Foreach-Object {
			            $key = "HKLM:\Software\$($_)\Classes\CLSID\$Item\Instance"
                        $clsidp = "HKLM:\Software\$($_)\Classes\CLSID"
                        if (Test-Path -Path $key -PathType Container) {
			                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                try {
	                                New-Object -Type pscustomobject -Property @{
	                                    Path = $key
	                                    Item = $_
                                        Value = (Get-ItemProperty -Path (Join-Path -Path $clsidp -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
	                                    Category = 'Codecs'
	                                }
                                } catch {
                                }		
			                }
                        }		
		            }			
	            }
                #endregion Codecs

                #region User Codecs

                # Drivers32
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKCU:\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name '*' @Category
	            }		

                # Filter
	            $key = 'HKCU:\Software\Classes\Filter'
                if (Test-Path -Path $key -PathType Container) {
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path 'HKCU:\SOFTWARE\Classes\CLSID' -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            Category = 'Codecs'
                        }			
		            }			
	            }

                # Instances
	            @('{083863F1-70DE-11d0-BD40-00A0C911CE86}','{AC757296-3522-4E11-9862-C17BE5A1767E}',
	            '{7ED96837-96F0-4812-B211-F13C24117ED3}','{ABE3B9A4-257D-4B97-BD1A-294AF496222E}') | Foreach-Object -Process {
		            $Item = $_
		            $null,'Wow6432Node' | Foreach-Object {
			            $key = "HKCU:\Software\$($_)\Classes\CLSID\$Item\Instance"
                        if (Test-Path -Path $key -PathType Container) {
			                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                try {
	                                New-Object -Type pscustomobject -Property @{
	                                    Path = $key
	                                    Item = $_
	                                    Value = (Get-ItemProperty -Path (Join-Path -Path 'HKCU:\SOFTWARE\Classes\CLSID' -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
	                                    Category = 'Codecs'
	                                }
                                } catch {
                                }		
			                }
                        }		
		            }			
	            }


                #endregion User Codecs
            }
            if ($All -or $OfficeAddins) {
                Write-Verbose -Message 'Looking for Office Addins entries'
                #region Office Addins

                <#
                # FileName value or
                # HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OneNote.OutlookAddin\CLSID
                #>
                $Category = @{ Category = 'Office Addins'}
                $null,'Wow6432Node' | Foreach-Object {
                    $arc = $_
                    'HKLM','HKCU' | ForEach-Object {
                        $root = $_
                        if (Test-Path "$($root):\SOFTWARE\$($arc)\Microsoft\Office") {
                            (Get-Item "$($root):\SOFTWARE\$($arc)\Microsoft\Office").GetSubKeyNames() | ForEach-Object {
                                if (Test-Path -Path (Join-Path -Path "$($root):\SOFTWARE\$($arc)\Microsoft\Office" -ChildPath "$($_)\Addins") -PathType Container) {
                                    $key = (Join-Path -Path "$($root):\SOFTWARE\$($arc)\Microsoft\Office" -ChildPath "$($_)\Addins")
                                    # Iterate through the Addins names
                                    (Get-item -Path $key).GetSubKeyNames() | ForEach-Object {
                                        try {
	                                        New-Object -Type pscustomobject -Property @{
	                                            Path = $key
	                                            Item = $_
	                                            Value = $(
                                                    $clsid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$($_)\CLSID" -Name '(default)' -ErrorAction Stop).'(default)';
                                                        if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\$arc\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)') {
                                                            (Get-ItemProperty -Path "HKLM:\SOFTWARE\$arc\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                                        } else {
                                                            $clsid
                                                        }
                                                        # (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                                ) # | Where-Object { $null -ne $_ } | Sort-Object -Unique # | Select-Object -First 1
                                                Category = 'Office Addins';
	                                        }
                                        } catch {

                                        }
                                    }

                                }
                            }
                        }
                    } # hklm or hkcu
                } 
                # Microsoft Office Memory Corruption Vulnerability (CVE-2015-1641)
                'HKLM','HKCU' | ForEach-Object {
                    $root = $_
                    $key = "$($root):\SOFTWARE\Microsoft\Office test\Special\Perf"
                    if (Test-Path "$($root):\SOFTWARE\Microsoft\Office test\Special\Perf") {
                        if ((Get-ItemProperty -Path "$($root):\SOFTWARE\Microsoft\Office test\Special\Perf" -Name '(default)' -ErrorAction SilentlyContinue).'(default)') {
	                        New-Object -Type pscustomobject -Property @{
	                            Path = $key
	                            Item = '(default)'
                                Value = (Get-ItemProperty -Path "$($root):\SOFTWARE\Microsoft\Office test\Special\Perf" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                Category = 'Office Addins';
	                        }
                        }
                    }
                }                
                #endregion Office Addins
            }
            if ($All -or $PrintMonitorDLLs) {
                Write-Verbose -Message 'Looking for Print Monitor DLLs entries'
                #region Print monitors
	            $Category = @{ Category = 'Print Monitors'}
	            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
		            Get-RegValue -Path "$key\$($_)" -Name 'Driver' @Category	
	            }
                #endregion Print monitors
            }
            if ($All -or $LSAsecurityProviders) {
                Write-Verbose -Message 'Looking for LSA Security Providers entries'
                #region LSA providers
	            $Category = @{ Category = 'LSA Providers'}

                # REG_SZ 
	            Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -Name 'SecurityProviders' @Category
	
                # REG_MULTI_SZ
	            'Authentication Packages','Notification Packages','Security Packages' | ForEach-Object {
		            $item = $_
                    (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name $_ @Category).Value | ForEach-Object {
                        if ($_ -ne '""') {
                            New-Object -Type pscustomobject -Property @{
                                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                                Item = $item
                                Value = $_
                                Category = 'LSA Providers'
                            }
                        }
                    }
	            }

                # HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
                if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -PathType Container) {
                    (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -Name 'Security Packages'  @Category).Value | ForEach-Object {
                        New-Object -Type pscustomobject -Property @{
                            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'
                            Item = 'Security Packages'
                            Value = $_
                            Category = 'LSA Providers'
                        }
                    }
                }
                #endregion LSA providers
            }
            if ($All -or $ServicesAndDrivers) {
                Write-Verbose -Message 'Looking for Services and Drivers'
                #region Services

                (Get-Item -Path 'HKLM:\System\CurrentControlSet\Services').GetSubKeyNames() | ForEach-Object {
                    $Type = $null
                    $key  = "HKLM:\System\CurrentControlSet\Services\$($_)"
                    try {
                        $Type = Get-ItemProperty -Path $key -Name Type -ErrorAction Stop
                    } catch {
                    }
                    if ($Type) {
                        Switch ($Type.Type) {
                            1  {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Drivers'
                                break
                            }
                            16 {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Services'
                                Get-RegValue -Path "$key\Parameters" -Name 'ServiceDll' -Category 'Services'
                                break
                            }
                            32 {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Services'
                                Get-RegValue -Path "$key\Parameters" -Name 'ServiceDll' -Category 'Services'
                                break
                            }
                            default { 
                                # $_ 
                            }
                        }
                    }
                }

                # Font drivers
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers' -Name '*' -Category 'Services'

                #endregion Services
            }

            if ($All -or $ScheduledTasks) {
                Write-Verbose -Message 'Looking for Scheduled Tasks'

                #region Scheduled Tasks

                Get-AllScheduledTask | Get-Task | ForEach-Object {
                    $Value = $null
                    $Value = if (
                        ($node = ([xml]$_.XML).Task.get_ChildNodes() | Where-Object { $_.Name -eq 'Actions'} ).HasChildNodes
                    ) {
                        # $node can have Exec or comHandler or both childs (ex: MediaCenter tasks)
                        switch ($($node.get_ChildNodes()).Name) {
                            Exec {
                                $subnode = ($node.get_ChildNodes() | Where-Object { $_.Name -eq 'Exec'})
                                if ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments'} | Select-Object -ExpandProperty '#text') {
                                    '{0} {1}' -f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command'} | Select-Object -ExpandProperty '#text'), 
                                    ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments'} | Select-Object -ExpandProperty '#text');
                                } else {
                                    $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command'} | Select-Object -ExpandProperty '#text' ; 
                                }
                                break;
                            }
                            ComHandler {
                                $subnode = ($node.get_ChildNodes() | Where-Object { $_.Name -eq 'ComHandler'})
                                if ($subnode.get_ChildNodes()| Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText) {
                                    '{0} {1}'-f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text'),
                                    ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText); 
                                } else {
                                    $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text'; 
                                }
                                break;
                            }
                            default {}
                        }
                    }

                    New-Object -Type pscustomobject -Property @{
                        Path = (Join-Path -Path "$($env:systemroot)\system32\Tasks" -ChildPath "$($_.Path)\$($_.Name)") ;
                        Item = $_.Name
                        Value =  $Value ;
                        Category = 'Task' ;
                    }
                }

                #endregion Scheduled Tasks
            }
            if ($All -or $Winlogon) {
                Write-Verbose -Message 'Looking for Winlogon entries'
                #region Winlogon
	            $Category = @{ Category = 'Winlogon'}
                Get-RegValue -Path 'HKLM:\SYSTEM\Setup' -Name 'CmdLine' @Category

	            'Credential Providers','Credential Provider Filters','PLAP Providers' | ForEach-Object {
		            $key = Join-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication' -ChildPath $_
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        New-Object -Type pscustomobject -Property @{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            Category = 'Winlogon'
                        }			
		            }
	            }  
                <# # deprecated
	            'System','SaveDumpStart' | ForEach-Object {
		            Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name $_ @Category	
	            }
                #>
    
                # Notify doesn't exist on Windows 8.1
                <# # deprecated
                if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -PathType Container) {
	                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
		                Get-RegValue -Path "$key\$($_)" -Name 'DLLName' @Category	
	                }
                }
                #>

	            if (Test-Path -Path 'HKLM:\System\CurrentControlSet\Control\BootVerificationProgram' -PathType Container) {
		            Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\BootVerificationProgram' -Name 'ImagePath' @Category
	            }
                #endregion Winlogon

                #region User Winlogon

                Get-RegValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'Scrnsave.exe' @Category

                Get-RegValue -Path 'HKCU:\Control Panel\Desktop' -Name 'Scrnsave.exe' @Category

                #endregion User Winlogon
            }
            if ($All -or $WMI) {
                Write-Verbose -Message 'Looking for WMI Database entries'

                # Temporary events created with Register-CimIndicationEvent or Register-WMIEvent
                <#
                Get-EventSubscriber -ErrorAction SilentlyContinue | ForEach-Object -Process {
                    $job = $_ | Select-Object -ExpandProperty Action
                    if ($job.Command) {
                        Write-Warning -Message 'A temporary WMI Event subscription was found'
                    }
                }
                #>
                # Permanent events
                Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue| Where-Object { $_.__CLASS -eq 'ActiveScriptEventConsumer' } | ForEach-Object {
                    if ($_.ScriptFileName) {
                        New-Object -Type pscustomobject -Property @{
                            Path = $_.__PATH ;
                            Item = $_.Name
                            Value =  $_.ScriptFileName ;
                            Category = 'WMI' ;
                        }
                    
                    } elseif ($_.ScriptText) {
                        New-Object -Type pscustomobject -Property @{
                            Path = $_.__PATH ;
                            Item = $_.Name
                            Value =  $null ;
                            Category = 'WMI' ;
                        }
                    } 
                }

                Get-WMIObject -Namespace root\Subscription -Class __EventConsumer -ErrorAction SilentlyContinue| Where-Object { $_.__CLASS -eq 'CommandlineEventConsumer' } | ForEach-Object {
                        New-Object -Type pscustomobject -Property @{
                            Path = $_.__PATH ;
                            Item = $_.Name
                            Value =  "$($_.WorkingDirectory)$($_.ExecutablePath)" ;# $($_.CommandLineTemplate)" ;
                            Category = 'WMI' ;
                        }
                }

            }
        }
        End {
        }
    }

    Function Get-PSPrettyAutorun {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
            [system.object[]]$RawAutoRun
        )
        Begin {}
        Process {
			if (-NOT $RawAutoRun) {
				# Handle nulls
				continue
			}
            $RawAutoRun | ForEach-Object {
                $Item = $_
				Write-Verbose "Found Autorun: [$($Item.Category)] $($Item.Value)"
                Switch ($Item.Category) {
                    Task {
                        Write-Verbose -Message "Reading Task $($Item.Path)"
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value ) {
                                #GUID
                                '^(\{)?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\})?' { 
                                    $clsid = ($_ -split '\s')[0]
                                    # $clsid = ([system.guid]::Parse( ($_ -split '\s')[0])).ToString('B')
                                    if (Test-Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\InprocServer32") -PathType Container) {
                                        Write-Verbose -Message 'Reading from InprocServer32'
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)' 
                                    } elseif (Test-Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\LocalServer32") -PathType Container) {
                                        Write-Verbose -Message 'Reading from LocalServer32'
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\LocalServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                    } else {
                                        try {
                                            Write-Verbose -Message 'Reading from AppID'
                                            # $appid = (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)") -Name 'AppId' -ErrorAction Stop).'AppId'
                                            "$($env:systemroot)\system32\sc.exe"
                                        } catch {
                                            # Write-Warning -Message "AppId not found for $clsid"
                                        }
                                    }
                                    break
                                }
                                # Rundll32
                                '^((%windir%|%(s|S)ystem(r|R)oot%)\\system32\\)?rundll32\.exe\s(/[a-z]\s)?.*,.*' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath (
                                        ([regex]'^((%windir%|%(s|S)ystem(r|R)oot%)\\system32\\)?rundll32\.exe\s(/[a-z]\s)?(%windir%\\system32\\)?(?<File>.*),').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # Windir\system32
                                '^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(s|S)ystem32\\.*\.(exe|vbs)' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath (
                                        ([regex]'^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(s|S)ystem32\\(?<File>.*\.(exe|vbs))(\s)?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # windir\somethingelse
                                '^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\.*\\.*\.(exe|vbs)' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath (
                                        ([regex]'^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(?<File>.*\\.*\.(exe|vbs))(\s)?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # special W7 case with media center
                                '^%SystemRoot%\\ehome\\.*\s' {
                                    # "$($env:systemroot)\ehome\ehrec.exe"
                                    Join-Path -Path "$($env:systemroot)\ehome" -ChildPath "$(
                                        ([regex]'^%SystemRoot%\\ehome\\(?<FileName>.*)\s').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    ).exe"
                                    break
                                }
                                # ProgramFiles
                                '^"?(C:\\Program\sFiles|%ProgramFiles%)\\' {
                                    Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                        ([regex]'^"?(C:\\Program\sFiles|%ProgramFiles%)\\(?<File>.*\.exe)("|\s)?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )                                        
                                    break
                                }
                                # ProgramFilesx86
                                '^"?(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\' {
                                    Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                        ([regex]'^"?(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\(?<File>.*\.exe)("|\s)?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # special powershell.exe
                                '^[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}\.[eE][xX][eE](\s)?' {
                                    "$($env:systemroot)\system32\WindowsPowerShell\v1.0\powershell.exe"
                                    break
                                }
                                # C:\users? 
                                '^[A-Za-z]:\\' {
                                    $_
                                    break;
                                }
                                # FileName.exe
                                '[a-zA-Z0-9]*\.exe(\s)?' {
                                # '[a-zA-Z0-9]*(\.exe\s)?' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath "$(
                                        ([regex]'^(?<FileName>[a-zA-Z0-9]*)(\.exe\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        ).exe"
                                    break
                                }
                                '^aitagent(\s/increment)?' {
                                    "$($env:systemroot)\system32\aitagent.exe"
                                    break
                                }
                                default {
                                    $_
                                }
                        } #endof switch
                        ) -Force -PassThru

                    break;
                    }
                    AppInit {
                        if ($Item.Value -eq [string]::Empty) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        } else {
                            # Switch ? malware example
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value "$($Item.Value)" -Force -PassThru
                        }
                        break
                    }
                    'Boot Execute' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^autocheck\sautochk\s' {
                                    "$($env:SystemRoot)\system32\autochk.exe"
                                    break;
                                }
                                default {
                                    $Item.Value
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    Codecs {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                        Switch -Regex ($Item.Value) {
                            '^[A-Z]:\\Windows\\' {
                                if ($Item.Path -match 'Wow6432Node') {
                                    $_ -replace 'system32','SysWOW64'
                                } else {
                                    $_
                                }
                                break
                            }
                            # '^[A-Z]:\\Program\sFiles' {
                            '^[A-Z]:\\[Pp]rogra' {
                                $_  | Get-NormalizedFileSystemPath
                                break
                            }
                            default {
                                if ($Item.Path -match 'Wow6432Node') {
                                    Join-Path "$($env:systemroot)\Syswow64" -ChildPath $_
                                } else {
                                    Join-Path "$($env:systemroot)\System32" -ChildPath $_
                                }
                            }
                        }
                        ) -Force -PassThru
                        break
                    }
                    Drivers {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            switch -Regex ($Item.Value) {
                                #'^\\SystemRoot\\System32\\drivers\\' {
                                '^\\SystemRoot\\System32\\' {
                                    $_ -replace '\\Systemroot',"$($env:systemroot)"
                                    break;
                                }
                                <#
                                '^System32\drivers\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                #>
                                '^System32\\[dD][rR][iI][vV][eE][rR][sS]\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                <#
                                '^system32\\DRIVERS\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                #>
                                '^\\\?\?\\C:\\Windows\\system32\\drivers' {
                                    $_ -replace '\\\?\?\\',''
                                    break;
                                }
                                '^System32\\CLFS\.sys' {
                                    $_ -replace 'System32\\',"$($env:systemroot)\system32\"
                                }
                                '^"?[A-Za-z]\\[Pp]rogram\s[fF]iles.*\\(?<FilePath>.*\\\.exe)\s?' {
                                    Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                        ([regex]'^"?[A-Za-z]\\[Pp]rogram\s[fF]iles.*\\(?<FilePath>.*\\\.exe)\s?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )                                        
                                    break
                                }
                                'SysmonDrv.sys' {
                                    $env:PATH -split ';'| ForEach-Object { 
                                        Get-ChildItem -Path $_\*.sys -Include SysmonDrv.sys -Force -EA 0 
                                    } | Select-Object -First 1 -ExpandProperty FullName
                                    break
                                }
                                default {
                                    $_
                                }
                        }) -Force -PassThru
                        break
                    }
                    Explorer {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            if ($Item.Value) {
                                if ($Item.Value -match '^[A-Z]:\\') {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        $Item.Value -replace 'system32','syswow64' | Get-NormalizedFileSystemPath
                                    } else {
                                        $Item.Value | Get-NormalizedFileSystemPath
                                    }
                                } else {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        Join-Path -Path "$($env:systemroot)\syswow64" -ChildPath $Item.Value
                                    } else {
                                        Join-Path -Path "$($env:systemroot)\system32" -ChildPath $Item.Value
                                    }
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Image Hijacks' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        break
                    }
                    'Internet Explorer' {
                        if ($Item.Item -ne 'Locked') {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                $Item.Value | Get-NormalizedFileSystemPath
                            ) -Force -PassThru
                        }
                        break
                    }
                    'Known Dlls' {
                        if ( (Test-Path -Path $Item.Value -PathType Container) -and ($Item.Item -match 'DllDirectory')) {
                        } else {
                            # Duplicate objects
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                            ) -Force -PassThru
                            if ([environment]::Is64BitOperatingSystem) {
                                $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                    Join-Path -Path "$($env:SystemRoot)\Syswow64" -ChildPath $Item.Value
                                ) -Force -PassThru
                            }
                        }
                        break
                    }
                    Logon {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            switch -Regex ($Item.Value) {
                                '\\Rundll32\.exe\s' {
                                    (($_ -split '\s')[1] -split ',')[0]
                                    break;
                                }
                                '\\Rundll32\.exe"' {
                                    (($_ -split '\s',2)[1] -split ',')[0] -replace '"',''
                                    break;
                                }
                                '^"[A-Z]:\\Program' {
                                    ($_ -split '"')[1]
                                    break;
                                }
                                '^"[A-Z]:\\Windows' {
                                    ($_ -split '"')[1]
                                    break;
                                }
                                'rdpclip' {
                                    "$($env:SystemRoot)\system32\$($_).exe"
                                    break
                                }
                                '^Explorer\.exe$' {
                                    "$($env:SystemRoot)\$($_)"
                                    break
                                }
                                # regsvr32.exe /s /n /i:U shell32.dll
                                '^regsvr32\.exe\s/s\s/n\s/i:U\sshell32\.dll' {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        "$($env:SystemRoot)\syswow64\shell32.dll"
                                    }else {
                                        "$($env:SystemRoot)\system32\shell32.dll"
                                    }
                                    break
                                }
                                '^C:\\Windows\\system32\\regsvr32\.exe\s/s\s/n\s/i:/UserInstall\sC:\\Windows\\system32\\themeui\.dll' {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        "$($env:SystemRoot)\syswow64\themeui.dll"
                                    }else {
                                        "$($env:SystemRoot)\system32\themeui.dll"
                                    }
                                    break
                                }
                                '^C:\\Windows\\system32\\cmd\.exe\s/D\s/C\sstart\sC:\\Windows\\system32\\ie4uinit\.exe\s\-ClearIconCache' {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        "$($env:SystemRoot)\syswow64\ie4uinit.exe"
                                    }else {
                                        "$($env:SystemRoot)\system32\ie4uinit.exe"
                                    }
                                    break
                                }
                                '^[A-Z]:\\Windows\\' {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        (($_ -split '\s')[0] -replace ',','') -replace 'System32','Syswow64'
                                    } else {
                                        (($_ -split '\s')[0] -replace ',','')
                                    }
                                    break
                                }
                                '^[a-zA-Z0-9]+\.(exe|dll)' {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        Join-Path -Path "$($env:SystemRoot)\syswow64" -ChildPath ($_ -split '\s')[0]
                                    } else {
                                        Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath ($_ -split '\s')[0]
                                    }
                                    break
                                }
                                '^RunDLL32\s' {
                                    Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath (($_ -split '\s')[1] -split ',')[0]
                                    break;
                                }

                                # ProgramFiles
                                '^[A-Za-z]:\\Program\sFiles\\' {
                                    Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                        @([regex]'[A-Za-z]:\\Program\sFiles\\(?<File>.*\.exe)\s?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )                                        
                                    break
                                }
                                # ProgramFilesx86
                                '^[A-Za-z]:\\Program\sFiles\s\(x86\)\\' {
                                    Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                        @([regex]'[A-Za-z]:\\Program\sFiles\s\(x86\)\\(?<File>.*\.exe)\s?').Matches($_) | 
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # C:\Users
                                '^"[A-Za-z]:\\' {
                                    ($_ -split '"')[1]
                                        break;
                                }
                                default {
                                    Write-Verbose -Message "default: $_"
                                    [string]::Empty
                                    # $_
                                }
                            } 
                        ) -Force -PassThru
                        break
                    }
                    'LSA Providers' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            if ($Item.Value -match '\.dll$') {
                                Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath $Item.Value
                            } else {
                                Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath "$($Item.Value).dll"
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Network Providers' {
                        $Item | Add-Member -MemberType ScriptProperty -Name ImagePath -Value $({$this.Value}) -Force -PassThru
                    }
                    'Office Addins' {
                        if ($Item.Path -match 'Wow6432Node' -and $Item.Value -imatch 'system32') {
                            $Item.Value = $Item.Value -replace 'system32','syswow64'
                        }
                        if ($Item.Value) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Switch -Regex ($Item.Value ) {
                                    #GUID
                                    '^(\{)?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\})?' { 
                                        ([system.guid]::Parse( ($_ -split '\s')[0])).ToString('B')
                                        break
                                    }
                                    default {
                                        $Item.Value -replace '"','' | Get-NormalizedFileSystemPath
                                    }
                                }
                            ) -Force -PassThru
                        }
                        break
                    }
                    'Print Monitors' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                        ) -Force -PassThru
                        break
                    }
                    Services {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(    
                            switch -Regex ($Item.Value) {
                            '^"?[A-Za-z]:\\[Ww][iI][nN][dD][oO][Ww][sS]\\' {
                                Join-Path -Path "$($env:systemroot)" -ChildPath (
                                    ([regex]'^"?[A-Za-z]:\\[Ww][iI][nN][dD][oO][Ww][sS]\\(?<FilePath>.*\.(exe|dll))\s?').Matches($_) | 
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )  
                                break
                            }
                            '^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FileName>.*\.[eE][xX][eE])\s?' {
                                Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                    ([regex]'^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FileName>.*\.[eE][xX][eE])\s?').Matches($_) | 
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )  
                                break
                            }
                            '^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\s\(x86\)\\(?<FileName>.*\.[eE][xX][eE])\s?' {
                                Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                    ([regex]'^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\s\(x86\)\\(?<FileName>.*\.[eE][xX][eE])\s?').Matches($_) | 
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )  
                                break
                            }
                            'winhttp.dll' {
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath 'winhttp.dll'
                                break
                            }
                            'atmfd.dll' {
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath 'atmfd.dll'
                                break
                            }
                            default {
                                $_
                            }

                        }) -Force -PassThru
                        break
                    }
                    Winlogon {
                        # this works on W8.1
                        # $Item | Add-Member -MemberType ScriptProperty -Name ImagePath -Value $({$this.Value}) -Force -PassThru
                        # for backward compatibility with W7 we do:
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^[a-zA-Z0-9]*\.[dDlL]{3}' {
                                    Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                                    break
                                }
                                default {
                                    $_;
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Winsock Providers' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^%SystemRoot%\\system32\\' {
                                    $_ -replace '%SystemRoot%',"$($env:SystemRoot)";
                                    break;
                                }
                                default {
                                    $_;
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    WMI {
                        if ($Item.Value) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $($Item.Value) -Force -PassThru
                            
                        } else {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        }
                        break
                    }
                    default {
                    }
                }
            }
        }
        End {}
    }

    Function Add-PSAutoRunExtendedInfo {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
            [system.object[]]$RawAutoRun
        )
        Begin {}
        Process {
			if (-NOT $RawAutoRun) {
				# Handle nulls
				continue
			}
            $RawAutoRun | ForEach-Object {
                $o = New-Object -Type PSCustomObject -Property @{
                        Path = $_.Path ;
                        Item = $_.Item ;
                        Category = $_.Category ;
                        Value = $_.Value
                        ImagePath = $_.ImagePath ;
                        Size = $null;
                        LastWriteTime = $null;
                        Version = $null;
                    }
                If ($_.ImagePath) {
                    try {
                        $extinfo = Get-Item -Path $_.ImagePath -ErrorAction Stop
                        $o.Size = $extinfo.Length;
                        $o.Version = $extinfo.VersionInfo.ProductVersion;
                        $o.LastWriteTime = $extinfo.LastWriteTime;
                        $o
                    } catch {
                        $o
                    }
                } else {
                    $o
                }
            }
        }
        End{}
    }

    Function Add-PSAutoRunHash {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
            [system.object[]]$RawAutoRun,
            [Switch]$ShowFileHash
        )
        Begin {}
        Process {
			if (-NOT $RawAutoRun) {
				# Handle nulls
				continue
			}
            $RawAutoRun | ForEach-Object {
                If ($ShowFileHash) {
					$_ | Add-Member -MemberType NoteProperty -Name MD5 -Value $null -Force
					$_ | Add-Member -MemberType NoteProperty -Name SHA1 -Value $null -Force
					$_ | Add-Member -MemberType NoteProperty -Name SHA256 -Value $null -Force
					$ImagePath = $_.ImagePath
                    if ($ImagePath) {
                        If (Test-Path -Path $ImagePath -PathType Leaf) {
							$_.MD5 = $(Get-FileHash -Path $ImagePath -Algorithm MD5).Hash
							$_.SHA1 = $(Get-FileHash -Path $ImagePath -Algorithm SHA1).Hash
							$_.SHA256 = $(Get-FileHash -Path $ImagePath -Algorithm SHA256).Hash
                        }
                    }
                }
                Write-Output $_
            }
        }
        End {}
    }
	
    Function Add-Sigcheck {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,ValueFromPipeLine=$true)]
            [system.object[]]$RawAutoRun,
            [Switch]$CheckSignatures
        )
        Begin {}
        Process {
			if (-NOT $RawAutoRun) {
				# Handle nulls
				continue
			}
            foreach( $r in $RawAutoRun ) { 
                If ($CheckSignatures) {			
					if ($r.ImagePath) {
						# Get hashes and verify Signatures with Sigcheck
						$Signature = Invoke-Sigcheck $r.ImagePath -GetHashes | Select -Property * -ExcludeProperty Path
						$Signature.PSObject.Properties | Foreach-Object {
							$r | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -Force
						}
                    }
                }
                Write-Output $r
            }
        }
        End {}
    }	


    #endregion Helperfunctions

}
Process {
    if ($PSBoundParameters.ContainsKey('ShowFileHash')) {
        $GetHash = $true
    } else {
        $GetHash = $false
    }
    if ($PSBoundParameters.ContainsKey('CheckSignatures')) {
        $CheckSig = $true
    } else {
        $CheckSig = $false
    }
    Get-PSRawAutoRun @PSBoundParameters | 
		Get-PSPrettyAutorun | 
			Add-PSAutoRunExtendedInfo | 
				Add-PSAutoRunHash -ShowFileHash:$GetHash | 
					Add-Sigcheck -CheckSignatures:$CheckSig
					
}
End {}
}

# Depreciated	
function Invoke-Autorunsc {
param(
	[String]$autorunscPath="C:\Windows\temp\autorunsc.exe"
)
	
	# Hardcode Hash (TODO: impliment more better authentication mechanism, maybe a signature check for MS)
	if ((Get-WmiObject -class win32_operatingsystem -Property OSArchitecture).OSArchitecture -match "64") {	
		$autorunsURL = "http://live.sysinternals.com/autorunsc64.exe"
	} else {
		$autorunsURL = "http://live.sysinternals.com/autorunsc.exe"
	}
	
	# Download Autoruns if not in the target directory & verify it's actually right sigcheck
	# $(get-AuthenticodeSignature myfile.exe).SignerCertificate.Subject <-- PS 3.0+
	if ( -NOT (Test-Path $autorunscPath) ) {
		$wc = New-Object System.Net.WebClient
		
		# Check if there is a proxy.  Explicitly Authenticated proxies are not yet supported.
		$proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
		if ($proxyAddr) {
			$proxy = new-object System.Net.WebProxy
			$proxy.Address = $proxyAddr
			$proxy.useDefaultCredentials = $true
			$wc.proxy = $proxy
		}
		try {
			$wc.DownloadFile($autorunsURL,$autorunscPath)
		} 
		catch {
			Write-Warning "ERROR[Invoke-Autoruns]: Could not download autoruns from Microsoft"
			return $null
		} 
		finally {
			$wc.Dispose()
		}
	}

	Write-Verbose 'Getting Autoruns via Autorunsc.exe -accepteula -a * -c -h -s *'
	$ar = (&"$autorunscPath" -accepteula -nobanner -a * -c *) | ConvertFrom-CSV | where { $_."Image Path" -ne "" } | Select Category,  
		@{Name="Name";Expression={$_.Entry}}, 
		@{Name="Key";Expression={$_."Entry Location"}}, 
		@{Name="PathName";Expression={$_."Image Path"}}, 
		@{Name="CommandLine";Expression={$_."Launch String"}},
		Description,
		Company,
		Version,
		Time,
		Enabled
	
	Foreach ($autorun in $ar) {		
		# Verify Signatures with Sigcheck (Yes, I know autoruns can get this but i'm normalizing formats and sigcheck gets more signature info)
		$Signature = Invoke-Sigcheck $autorun.PathName -GetHashes | Select -Property * -ExcludeProperty Path,Company,Version,Description,PESHA1,PESHA256,IMP
		$Signature.PSObject.Properties | Foreach-Object {
			$autorun | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value -force
		}
	}	
	return $ar
}

function Get-DiskInfo {
	Write-Verbose "Getting Disk info"
	# Get Disks Installed
	# return gwmi -Class Win32_LogicalDisk | Select DeviceID, DriveType, FreeSpace, Size, VolumeName, FileSystem
	
	$disks = gwmi -Class win32_logicaldisk | 
		Select Name,
		@{Name="Freespace";Expression={"{0:N1} GB" -f ($_.Freespace / 1000000000)}},
		@{Name="Size";Expression={"{0:N1} GB" -f ($_.Size / 1000000000)}},
		FileSystem,
		VolumeSerialNumber,
		DriveType
									
	Switch ($disks.DriveType) {
		0 { $disks.DriveType = "Unknown (0)"; break}
		1 { $disks.DriveType = "No Root Directory (1)"; break}
		2 { $disks.DriveType = "Removable Disk (2)"; break}
		3 { $disks.DriveType = "Local Disk (3)"; break}
		4 { $disks.DriveType = "Network Drive (4)"; break}
		5 { $disks.DriveType = "Compact Disc (5)"; break}		
		6 { $disks.DriveType = "RAM Disk (6)"; break}	
	}

	return $disks
}

function Get-Pipes {
	Write-Verbose "Getting NamedPipes"
	# Get all Named pipes
	try {
		$NamedPipes = [System.IO.Directory]::GetFiles("\\.\pipe\")
	} catch {
		# Will fail if pipe has an illegal name for path objects
	}
	
	# Get null session pipes and shares (these are generally bad - used by legacy Win2k era applications and malware that do lateral C2 via NamedPipes)
	$NullSessionPipes = (Get-ItemProperty -ea 0 HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters).nullsessionpipes
	$NullSessionShares = (Get-ItemProperty -ea 0 HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters).NullSessionShares
	
	$Pipes = new-Object PSObject -Property @{
		NamedPipes			= $NamedPipes
		NullSessionPipes	= $nullSessionPipes
		NullSessionShares	= $NullSessionShares
	}
	return $Pipes
}

function Get-HostInfo {
	# Gather System and Operating System Information from WMI or Cim (Cim = Powershell 3.0+ unfortunately)
	# If you are 3.0+, please use Cim.  WMI is being depreciated.
	# Difference: WMI sits on top of DCOM, Cim sits on top of WinRM
	# Example: 
	# Get-WmiObject Win32_ComputerSystem
	# Get-CimInstance -Class Win32_ComputerSystem
	
	$SystemInfo = Get-WmiObject Win32_ComputerSystem | Select Name,DNSHostName,Domain,Workgroup,SystemType,@{Name = 'CurrentTimeZone'; Expression = {$_.CurrentTimeZone/60}},Manufacturer,Model,DomainRole
	Switch ($Systeminfo.DomainRole) {
		0 { $Systeminfo.DomainRole = "Standalone Workstation (0)"; break}
		1 { $Systeminfo.DomainRole = "Member Workstation (1)"; break}
		2 { $Systeminfo.DomainRole = "Standalone Server (2)"; break}
		3 { $Systeminfo.DomainRole = "Member Server (3)"; break}
		4 { $Systeminfo.DomainRole = "Backup Domain Controller (4)"; break}
		5 { $Systeminfo.DomainRole = "Primary Domain Controller (5)"; break}		
	}
	
	$OS = Get-wmiobject Win32_OperatingSystem | 
		Select @{Name = 'OS'; Expression = {$_.Caption}},
		Version,
		CSDVersion,
		OSArchitecture,
		@{Name = 'InstallDate'; Expression = {$_.ConvertToDateTime($_.InstallDate).ToString()}},
		@{Name = 'LastBootUpTime'; Expression = {$_.ConvertToDateTime($_.LastBootUpTime).ToString()}},
		@{Name = 'LocalDateTime'; Expression = {$_.ConvertToDateTime($_.LocalDateTime).ToString()}}
		
	$OS.PSObject.Properties | Foreach-Object {
		$SystemInfo | Add-Member -type NoteProperty -Name $_.Name -Value $_.Value
	}
	
	# Grab the path variable (might be useful?)
	$SystemInfo | Add-Member -type NoteProperty -Name EnvPath -Value $env:Path
	
	Return $SystemInfo 
}

function Get-InterestingStuff {
	# Pending File Rename Operations (Can delete stuff on reboot. Set when people want to delete something that's locked by OS -- like your log files)
	$PendingFileRename = (get-itemproperty "HKLM:\System\CurrentControlSet\Control\Session Manager").PendingFileRenameOperations
	
	$InterestingStuff = new-Object PSObject -Property @{
		PendingFileRename	= $PendingFileRename
	}
	return $InterestingStuff
}

function Get-AccountInfo {
	Write-Verbose "Getting Account Info"
	# Net User can be a heavy load on domain controllers because all domain accounts are local to a domain controller

	# LastLogon = yyyymmddhhmmss.mmmmmm

    # User to SID - This will give you a Domain User's SID
    # $objUser = New-Object System.Security.Principal.NTAccount("DOMAIN_NAME", "USER_NAME") 
    # $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).Value 
    
    # SID to Domain User - This will allow you to enter a SID and find the Domain User

    # $SID = "S-1-5-21-1031827263-1101308967-1021258693-501"
    # $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID) 
    # $objUser = $objSID.Translate( [System.Security.Principal.NTAccount]).Value 


    $LocalAccounts = gwmi win32_useraccount -Filter "LocalAccount='True'" | Select Caption,
        Description,
        AccountType,
        Disabled,
        Domain,
        FullName,
        @{Name = 'InstallDate'; Expression = {$_.ConvertToDateTime($_.InstallDate).ToString()}},
        LocalAccount,
        SID,
        SIDType,
        Lockout,
		Comment

	# Login history (Note: NumberOfLogons is maintained seperately on each DC - so it's usually smaller than it should be)
	$logins = gwmi -Class Win32_NetworkLoginProfile -Filter "Privileges='2'"| Select Name,Comment,BadPasswordCount,AccountExpires,Description,FullName, 
        @{Name = 'LastLogon'; Expression = {$_.ConvertToDateTime($_.LastLogon).ToString()}},
        @{Name = 'LastLogoff'; Expression = { if ( $_.LastLogoff -notmatch "\*\*\*") { $_.ConvertToDateTime($_.LastLogoff).ToString()}  }},
        NumberOfLogons,UserType,UserId,UserComment,
		@{Name = 'Privileges'; Expression = { 
				Switch ($_.Privileges) { 
					0 { "Guest (0)" }
					1 { "User (1)" }
					2 { "Administrator (2)" }
				} 
			}
		}

	$logins | Foreach-Object {
		# Add SIDs
		$Domain = ($_.Name).Split("\\")[0]
		$Username = ($_.Name).Split("\\")[1]
		try { 
			$UserObj = New-Object System.Security.Principal.NTAccount($Domain, $Username) 
			$UserSID = $UserObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
		} catch { 
			Write-Warning "Could not get SID for $Domain\$Username"
		}
		$_ | Add-Member -type NoteProperty -Name UserSID -Value $UserSID
	}
	
	# Get Local Admins
	$LocalAdministratorMembers = Gwmi win32_groupuser | ? { $_.groupcomponent -like '*"Administrators"'} | % { 
		$_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $null
		$matches[1].trim('"') + "\" + $matches[2].trim('"') 
	} 
        
	$RDPHistory = gci -ea 0 "HKCU:\Software\Microsoft\Terminal Server Client" | ForEach-Object {Get-ItemProperty -ea 0 $_.pspath} 
	
	#	Retrieves the date/time that users logged on and logged off on the system.
	# Version 3.0+ - I borrowed this from Jacob Soo (@jacobsoo) 
	$WinLogonEvents = Get-EventLog System -Source Microsoft-Windows-Winlogon | Select @{n="Time";e={$_.TimeGenerated}},
		@{n="User";e={(New-Object System.Security.Principal.SecurityIdentifier $_.ReplacementStrings[1]).Translate([System.Security.Principal.NTAccount])}}, 
		@{n="Action";e={if($_.EventID -eq 7001) {"Logon"} else {"Logoff"}}}
		
	
	$accountinfo = new-Object PSObject -Property @{
		LocalAccounts				= $LocalAccounts
		LoginHistory				= $logins
		LocalAdministratorMembers 	= $LocalAdministratorMembers
		RDPHistory					= $RDPHistory
		WinLogonEvents				= $WinLogonEvents
		}
		
	return $accountinfo
}

function Get-InstalledApps {
<#
.SYNOPSIS
Get the list of installed applications on a system.
Author: Jacob Soo (@jacobsoo)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
Get the list of installed applications on a system.
.EXAMPLE
PS C:\>Get-Installed-Apps
Description
-----------
Get the list of installed applications on a system.
#>

	$InstalledAppsList = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ea 0 | where { 
		$_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, DisplayIcon
		
	$InstalledAppsList += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ea 0 | where { 
		$_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, DisplayIcon 
		
	return $InstalledAppsList
}

function Get-FirewallRules {
	#http://blogs.technet.com/b/heyscriptingguy/archive/2010/07/03/hey-scripting-guy-weekend-scripter-how-to-retrieve-enabled-windows-firewall-rules.aspx
	#Create the firewall com object to enumerate 
	$fw = New-Object -ComObject HNetCfg.FwPolicy2 
	#Retrieve all firewall rules 
	$FirewallRules = $fw.rules 
	#create a hashtable to define all values
	$fwprofiletypes = @{1GB="All";1="Domain"; 2="Private" ; 4="Public"}
	$fwaction = @{1="Allow";0="Block"}
	$FwProtocols = @{1="ICMPv4";2="IGMP";6="TCP";17="UDP";41="IPV6";43="IPv6Route"; 44="IPv6Frag";
			  47="GRE"; 58="ICMPv6";59="IPv6NoNxt";60="IPv60pts";112="VRRP"; 113="PGM";115="L2TP"}
	$fwdirection = @{1="Inbound"; 2="Outbound"} 

	#Retrieve the profile type in use and the current rules

	$fwprofiletype = $fwprofiletypes.Get_Item($fw.CurrentProfileTypes)
	$fwrules = $fw.rules

	"Current Firewall Profile Type in use: $fwprofiletype"
	$AllFWRules = @()
	#enumerate the firewall rules
	$fwrules | ForEach-Object{
		#Create custom object to hold properties for each firewall rule 
		$FirewallRule = New-Object PSObject -Property @{
			ApplicationName = $_.Name
			Protocol = $fwProtocols.Get_Item($_.Protocol)
			Direction = $fwdirection.Get_Item($_.Direction)
			Action = $fwaction.Get_Item($_.Action)
			LocalIP = $_.LocalAddresses
			LocalPort = $_.LocalPorts
			RemoteIP = $_.RemoteAddresses
			RemotePort = $_.RemotePorts
		}

		$AllFWRules += $FirewallRule

		
	} 
	return $AllFWRules
}

function Get-NetworkConfig {
	Write-Verbose "Getting Network Configuration"
	# ============ Surveying Network Configuration ===========================
	# OnlyConnectedNetworkAdapters
	# $ipconfig = gwmi -Class Win32_NetworkAdapterConfiguration | Where { $_.IPEnabled -eq $true } `
		# | Format-List @{ Label="Computer Name"; Expression= { $_.__SERVER }}, IPEnabled, Description, MACAddress, IPAddress, `
		# IPSubnet, DefaultIPGateway, DHCPEnabled, DHCPServer, @{ Label="DHCP Lease Expires"; Expression= { [dateTime]$_.DHCPLeaseExpires }}, `
		# @{ Label="DHCP Lease Obtained"; Expression= { [dateTime]$_.DHCPLeaseObtained }}

	$hosts 	= (Get-Content c:\windows\system32\drivers\etc\hosts | select-string -notmatch "^#").ToString().Trim()
		
	$routes = @()
	$temp = netstat -nr | Out-String 
	$routes += "IPv4 " + $temp.Substring( $temp.IndexOf("Persistent"), ($temp.IndexOf("IPv6")-$temp.IndexOf("Persistent")) )
	$routes += "IPv6 " + $temp.Substring( $temp.LastIndexOf("Persistent") )

#		routes 		= gwmi -Class Win32_IP4RouteTable | Select Description, Name, InterfaceIndex, NextHop, Status, Type, InstallDate, Age

	$ipconfig = gwmi -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" | Select DHCPEnabled, 
		IPAddress, DefaultIPGateway, DNSDomain, ServiceName, Description, Index, 
		@{Name = 'DHCPLeaseObtained'; Expression = {$_.ConvertToDateTime($_.DHCPLeaseObtained).ToString()}},
		@{Name = 'DHCPLeaseExpires'; Expression = {$_.ConvertToDateTime($_.DHCPLeaseExpires).ToString()}}
	
	$Shares = gwmi -Class Win32_Share | Select Description, Name, Path, Status, 
		InstallDate, 
		@{Name = 'Type'; Expression = {
				switch ($_.Type) {
					0 { "Disk Drive (0)" }
					1 { "Print Queue (1)" }
					2 { "Device (2)" }
					3 { "IPC (3)" }
					2147483648 { "Disk Drive Admin (2147483648)" }
					2147483649 { "Print Queue Admin (2147483649)" }
					2147483650 { "Device Admin (2147483650)" }
					2147483651 { "IPC Admin (2147483651)" }
				}
			}
		}
	
	$Connections = gwmi -Class Win32_NetworkConnection | Select Name, 
		Status, ConnectionState, Persistent, LocalName, RemoteName, 
		RemotePath, InstallDate, ProviderName,DisplayType,UserName
	
	$netconfig = new-Object PSObject -Property @{
		Ipconfig	= $ipconfig
		Hosts 		= $hosts
		Routes 		= $routes
		Shares		= $Shares
		Arp 		= arp -a #TODO: objectify this... 
		Connections	= $Connections
		NetSessions	= net session #TODO: objectify this... 
		}
		
	return $netconfig
}

# Useless in PS 2.0 but awesome for those rare PS 5.0 boxes
Function Find-PSScriptsInPSAppLog {
<#
.SYNOPSIS
Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.
Function: Find-AppLockerLogs
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.
.EXAMPLE
Find-PSScriptsInPSAppLog
Find unique PowerShell scripts being executed from the PowerShell operational log.
.NOTES
.LINK
Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}
    $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Where {$_.Id -eq 4100}

    foreach ($Log in $Logs)
    {
        $ContainsScriptName = $false
        $LogDetails = $Log.Message -split "`r`n"

        $FoundScriptName = $false
        foreach($Line in $LogDetails)
        {
            if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
            {
                $ScriptName = $Matches[1]
                $FoundScriptName = $true
            }
            elseif ($Line -imatch "^\s*User\s=\s(.*)")
            {
                $User = $Matches[1]
            }
        }

        if ($FoundScriptName)
        {
            $Key = $ScriptName + "::::" + $User

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    ScriptName = $ScriptName
                    UserName = $User
                    Count = 1
                    Times = @($Log.TimeCreated)
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Log.TimeCreated
            }
        }
    }

    return $ReturnInfo
}

# Broken until Mark fixes CSV output on the -t option.  Use of comma delimited fields mangles CSV output (-t -c)
function Get-RootCertificateStore {
	Param(
		[string] $SigcheckPath="C:\Windows\temp\sigcheck.exe"
	)
	
	# HKLM:\Software\Microsoft\SystemCertificates\AuthRoot\Certificates\
	# HKLM:\Software\Microsoft\SystemCertificates\Certificates\
	# 
	# HKLM:\Software\Microsoft\SystemCertificates\MY\Certificates
	# HKLM:\Software\Microsoft\SystemCertificates\CA\Certificates
	# HKLM:\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates
	# HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\
	
	# Hardcode Hash (TODO: impliment better authentication mechanism, maybe a signature check for MS)
	if ((Get-WmiObject -class win32_operatingsystem -Property OSArchitecture).OSArchitecture -match "64") {	
		$SigcheckURL = "http://live.sysinternals.com/sigcheck64.exe"
		$SigcheckHash = "860CECD4BF4AFEAC0F6CCCA4BECFEBD0ABF06913197FC98AB2AE715F382F45BF"
	} else {
		$SigcheckURL = "http://live.sysinternals.com/sigcheck.exe"
		$SigcheckHash = "92A9500E9AF8F2FBE77FB63CAF67BD6CC4CC110FA475ADFD88AED789FB515E6A"
	}
	
	# Download Autoruns if not in the target directory and it's the right file
	# $(get-AuthenticodeSignature myfile.exe).SignerCertificate.Subject <-- PS 3.0+
	if ( Test-Path $SigcheckPath ) {
	
	} else {
		$wc = New-Object System.Net.WebClient
		
		# Check if there is a proxy.  Explicitly Authenticated proxies are not yet supported.
		if (Get-Item "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\proxyserver" -ea 0) {
			$proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
			$proxy = new-object System.Net.WebProxy
			$proxy.Address = $proxyAddr
			$proxy.useDefaultCredentials = $true
			$wc.proxy = $proxy
		}
		try {
			$wc.DownloadFile($SigcheckURL,$SigcheckPath)
		} 
		catch {
			Write-Warning "Could not download sigcheck from Microsoft"
			return $null
		} 
		finally {
			$wc.Dispose()
		}
	}
	
	<#

	#>
	Write-Verbose 'Verifying Digital Signatures via sigcheck.exe -accepteula -a * -c -h -s *'
	$TrustStores = (&"$SigcheckPath" -accepteula -t -c) | Select -skip 5 | ConvertFrom-CSV
	
	# Note - this utility won't parse as there is a bug in the csv output of -t which uses an arbitrary number of comma seperated fields within
	# the "Valid Usage" field.  So CSV parsing is out.
	<#
	GeoTrust Primary Certification Authority - G3
     Cert Status:    Valid
     Valid Usage:    Server Auth, Client Auth, Email Protection, Code Signing, Timestamp Signing
     Cert Issuer:    GeoTrust Primary Certification Authority - G3
     Serial Number:  15 AC 6E 94 19 B2 79 4B 41 F6 27 A9 C3 18 0F 1F
     Thumbprint:     039EEDB80BE7A03C6953893B20D2D9323A4C2AFD
     Algorithm:      sha256RSA
     Valid from:     7:00 PM 4/1/2008
     Valid to:       6:59 PM 12/1/2037
	#>
	
	return $TrustStores
}

#endregion Collector Functions 

#region Helper Functions:
function Invoke-Sigcheck {
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string] $FilePath,
		
		[string] $SigcheckPath="C:\Windows\temp\sigcheck.exe",
		
		[switch] $GetHashes
	)
	# Hardcode Hash (TODO: impliment more better authentication mechanism, maybe a signature check for MS)
	if ([IntPtr]::Size -eq "8") {	
		$SigcheckURL = "http://live.sysinternals.com/sigcheck64.exe"
	} else {
		$SigcheckURL = "http://live.sysinternals.com/sigcheck.exe"
	}
	
	# Download SigCheck if not in the target directory (might want to verify it's the right SigCheck before running this)
	if ( -NOT (Test-Path $SigcheckPath) ) {
		if (Invoke-DownloadFile $SigcheckURL $SigcheckPath) { 
			Write-Verbose "Downloaded Sigcheck!"
		} else { 
			Write-Warning "ERROR[Invoke-Sigcheck]: Could not download SigCheck from Microsoft"
			return $null
		}	
	}
	
<#
	Path            : c:\windows\temp\autorunsc.exe
	Verified        : Signed
	Date            : 12:43 PM 7/6/2016
	Publisher       : Microsoft Corporation
	Company         : Sysinternals - www.sysinternals.com
	Description     : Autostart program viewer
	Product         : Sysinternals autoruns
	Product Version : 13.61
	File Version    : 13.61
	Machine Type    : 64-bit
	Binary Version  : 13.61.0.0
	Original Name   : autoruns.exe
	Internal Name   : Sysinternals Autoruns
	Copyright       : Copyright (C) 2002-2016 Mark Russinovich
	Comments        : n/a
	Entropy         : 5.966
	MD5             : 3DB29814EA5A2091425200B58E25BA15
	SHA1            : E33A2A83324731F8F808B2B1E1F5D4A90A9B9C33
	PESHA1          : B4DC9B4C6C053ED5D41ADB85DCDC8C8651D478FC
	PESHA256        : 6C7E61FE0FBE73E959AA78A40810ACD1DB3B308D9466AA6A4ACD9B0356B55B5B
	SHA256          : D86C508440EB2938639006D0D021ADE7554ABB2D1CFAA88C1EE1EE324BF65EC7
	IMP             : FA51BDCED359B24C8FCE5C35F417A9AF
#>
	
	if ($GetHashes) {
		Write-Verbose "Verifying Digital Signatures via sigcheck.exe -accepteula -nobanner -c -h -a $FilePath"
		$Signature = (&"$SigcheckPath" -accepteula -nobanner -c -a -h $FilePath) | ConvertFrom-CSV | Select -Property * -ExcludeProperty PESHA1,PESHA256,IMP | where { 
			$_.Path -ne "No matching files were found." } 
		
	} else {
		Write-Verbose "Verifying Digital Signatures via sigcheck.exe -accepteula -nobanner -c -a $FilePath"
		$Signature = (&"$SigcheckPath" -accepteula -nobanner -c -a $FilePath) | ConvertFrom-CSV | where {
			$_.Path -ne "No matching files were found." }
		
	}

	return $Signature
}

function Get-Hashes {
# Perform Cryptographic hash on a file
#
# @param path		File to hash
# @param Type	    Type of hashing to conduct
#
# Returns:			[Object] Path, MD5, SHA1, SHA256.  All uppercase hex without byte group delimiters
	Param(
	    [Parameter(
			Position=0,
			ValueFromPipeline = $true,
			ValueFromPipelineByPropertyName = $true
			)]
		[Alias("FullName")]
		[String]$Path,

		[Parameter(Position=1)]
        [ValidateSet('MD5','SHA1','SHA256','All')]
		[string[]]$Type = @('ALL')
	) 

	BEGIN {
		# Initialize Cryptoproviders

		if (-NOT $Global:CryptoProvider) {
			try { $MD5CryptoProvider = new-object -TypeName system.security.cryptography.MD5CryptoServiceProvider } catch { $MD5CryptoProvider = $null }
			try { $SHA1CryptoProvider = new-object -TypeName system.security.cryptography.SHA1CryptoServiceProvider } catch { $SHA1CryptoProvider = $null }
			try { $SHA256CryptoProvider = new-object -TypeName system.security.cryptography.SHA256CryptoServiceProvider } catch { $SHA256CryptoProvider = $null }
			
			$Global:CryptoProvider = New-Object PSObject -Property @{
				MD5CryptoProvider = $MD5CryptoProvider
				SHA1CryptoProvider = $SHA1CryptoProvider
				SHA256CryptoProvider = $SHA256CryptoProvider
			}	
		}
		Write-Debug "Before $Global:CryptoProvider"
	}
	
	PROCESS {
		
		try {
			$inputBytes = [System.IO.File]::ReadAllBytes($Path);
		} catch {
			Write-Warning "Hash Error: Could not read file $Path"
			return $null
		}
		
		$Results = New-Object PSObject -Property @{
			Path = $Path
			MD5 = $null
			SHA1 = $null
			SHA256 = $null
		}
		
		Switch ($Type) {
			All {
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.MD5CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with MD5CryptoProvider"
					$result = $null
				}
				$Results.MD5 = $result
				
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA1CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA1CryptoProvider"
					$result = $null
				}
				$Results.SHA1 = $result
				
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA256CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA256CryptoProvider"
					$result = $null
				}
				$Results.SHA256 = $result
				break;
			}
			MD5 { 
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.MD5CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with MD5CryptoProvider"
					$result = $null
				}
				$Results.MD5 = $result			
			}
			SHA1 {
				Write-Verbose "Type: SHA1"
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA1CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA1CryptoProvider"
					$result = $null
				}
				$Results.SHA1 = $result
			}
			SHA256 {
				try {
					$Hash = [System.BitConverter]::ToString($Global:CryptoProvider.SHA256CryptoProvider.ComputeHash($inputBytes))
					$result = $Hash.Replace('-','').ToUpper()
				} catch {
					Write-Warning "Hash Error: Could not compute Hash $Path with SHA256CryptoProvider"
					$result = $null
				}
				$Results.SHA256 = $result
			}
		}

		Write-Output $Results
	}
	
	END {}
}

function Invoke-DownloadFile {
# Need this in Powershell V2, otherwise us Invoke-WebRequest (aka wget)
# Return true if file downloaded, otherwise false/null
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[String]$Url,
		[Parameter(Position=1, Mandatory=$True)]
		[String]$Path
	)
	$wc = New-Object System.Net.WebClient
	
	# GetSystemWebProxy method reads the current user's Internet Explorer (IE) proxy settings. 
	$proxy = [System.Net.WebRequest]::GetSystemWebProxy()
	# Check if there is a proxy.  Explicitly Authenticated proxies are not yet supported.
	
	$wc.Proxy = $proxy
	$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
	# $proxyAddr = (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer
	# $wc.proxy.Address = $proxyAddr
	
	try {
		$wc.DownloadFile($Url,$Path)
		return $true
	} 
	catch {
		Write-Warning "Could not download file from $Url -> $Path"
		return $false
	} 
	finally {
		$wc.Dispose()
	}
}

function Get-ParsedSystemPath {
	Param(
		[Parameter(Position=0, Mandatory=$True)]
		[ValidateNotNullOrEmpty()]	
		[string]$inputStr
	)

	# PathName extractor
	#[regex]$pathpattern = '(\b[a-z]:\\(?# Drive)(?:[^\\/:*?"<>|\r\n]+\\)*)(?# Folder)([^\\/:*?"<>|\r\n,\s]*)(?# File)'
	#[regex]$pathpattern = "((?:(?:%\w+%\\)|(?:[a-z]:\\)){1}(?:[^\\/:*?""<>|\r\n]+\\)*[^\\/:*?""<>|\r\n]*\.(?:exe|dll|sys))"
	# [System.Environment]::ExpandEnvironmentVariables("%SystemRoot%\System32\Winevt\Logs\DebugChannel.etl")
	
    $str = $inputStr.ToLower()

	#Check for paths with no drive letter:
	if ($str.StartsWith('"')) {
		#$str = $str.Replace('"', '')
        #$str -replace 
	}	
	if ($str.StartsWith('\??\')) {
		$str = $str.Replace('\??\', '')
	}
	if ($str -match '%systemroot%') {
		$str = $str.Replace("%systemroot%", "$env:SystemRoot")
	}
	if ($str -match "%programfiles%") {
		$str = $str.Replace("%programfiles%", "$env:programfiles")
	}
	if ($str -match "%windir%") {
		$str = $str.Replace("%windir%", "$env:windir")
	}	
	if ($str -match "\\systemroot") {
		$str = $str.Replace('\systemroot', "$env:SystemRoot")
	}
	if ($str.StartsWith("system32")) {
		$str = $env:windir + "\" + $str
	}
	if ($str.StartsWith("syswow64")) {
		$str = $env:windir + "\" + $str
	}

	# Match Regex of File Path
	$regex = '(\b[a-z]:\\(?# Drive)(?:[^\\/:*?"<>|\r\n]+\\)*)(?# Folder)([^\\/:*?"<>|\r\n,\s]*)(?# File)'
	$matches = $str | select-string -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value }
	
	if ($matches.count -gt 1) {
		Write-Verbose "Multiple paths found $matches"
		$matches | % { Write-Warning "==Match Found! $_" }
		return $matches[0].ToLower()			
	} else {
		return $matches.ToLower()
	}
	# Write-Verbose "Matches: $str --> $matches"
	
	#if ($str -match "@\w+\.dll,") {
	#	$str = $env:windir + "\system32\" + $str.Split(",")[0].Substring(1)
	#}	
}

function Convert-BinaryToString {
    [CmdletBinding()]
    param (
        [string] $FilePath
    )

	# $Content = Get-Content -Path $FilePath -Encoding Byte
	# $Base64 = [System.Convert]::ToBase64String($Content)
	# $Base64 | Out-File $FilePath.txt
	# http://trevorsullivan.net/2012/07/24/powershell-embed-binary-data-in-your-script/
	
    try {
        $ByteArray = [System.IO.File]::ReadAllBytes($FilePath);
    }
    catch {
        throw "Failed to read file. Please ensure that you have permission to the file, and that the file path is correct.";
    }

    if ($ByteArray) {
        $Base64String = [System.Convert]::ToBase64String($ByteArray);
    }
    else {
        throw '$ByteArray is $null.';
    }

    Write-Output -InputObject $Base64String;
}

function Convert-StringToBinary {
    [CmdletBinding()]
    param (
          [string] $InputString
        , [string] $FilePath = ('{0}\{1}' -f $env:TEMP, [System.Guid]::NewGuid().ToString())
    )
	# $TargetFile = Convert-StringToBinary -InputString $NewExe -FilePath C:\temp\new.exe;
	# Start-Process -FilePath $TargetFile.FullName;
	# http://trevorsullivan.net/2012/07/24/powershell-embed-binary-data-in-your-script/
	
	if (Test-Path $FilePath) { Remove-Item $FilePath -force }
	
    try {
        if ($InputString.Length -ge 1) {
            $ByteArray = [System.Convert]::FromBase64String($InputString);
            [System.IO.File]::WriteAllBytes($FilePath, $ByteArray);
        }
    }
    catch {
        throw ('Failed to create file from Base64 string: {0}' -f $FilePath);
    }

    Write-Output -InputObject (Get-Item -Path $FilePath);
}

function Get-Entropy {
<#
.SYNOPSIS

Calculates the entropy of a file or byte array.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.PARAMETER ByteArray

Specifies the byte array containing the data from which entropy will be calculated.

.PARAMETER FilePath

Specifies the path to the input file from which entropy will be calculated.

.EXAMPLE

Get-Entropy -FilePath C:\Windows\System32\kernel32.dll

.EXAMPLE

ls C:\Windows\System32\*.dll | % { Get-Entropy -FilePath $_ }

.EXAMPLE

C:\PS>$RandArray = New-Object Byte[](10000)
C:\PS>foreach ($Offset in 0..9999) { $RandArray[$Offset] = [Byte] (Get-Random -Min 0 -Max 256) }
C:\PS>$RandArray | Get-Entropy

Description
-----------
Calculates the entropy of a large array containing random bytes.

.EXAMPLE

0..255 | Get-Entropy

Description
-----------
Calculates the entropy of 0-255. This should equal exactly 8.

.OUTPUTS

System.Double

Get-Entropy outputs a double representing the entropy of the byte array.
#>

    [CmdletBinding()] Param (
        [Parameter(Mandatory = $True, Position = 0, ValueFromPipeline = $True, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $ByteArray,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'File')]
        [ValidateNotNullOrEmpty()]
        [IO.FileInfo]
        $FilePath
    )

    BEGIN
    {
        $FrequencyTable = @{}
        $ByteArrayLength = 0
    }

    PROCESS
    {
        if ($PsCmdlet.ParameterSetName -eq 'File')
        {
            $ByteArray = [IO.File]::ReadAllBytes($FilePath.FullName)
        }

        foreach ($Byte in $ByteArray)
        {
            $FrequencyTable[$Byte]++
            $ByteArrayLength++
        }
    }

    END
    {
        $Entropy = 0.0

        foreach ($Byte in 0..255)
        {
            $ByteProbability = ([Double] $FrequencyTable[[Byte]$Byte]) / $ByteArrayLength
            if ($ByteProbability -gt 0)
            {
                $Entropy += -$ByteProbability * [Math]::Log($ByteProbability, 2)
            }
        }

        Write-Output $Entropy
    }
}

function Get-SystemInfo {
<#
.SYNOPSIS

A wrapper for kernel32!GetSystemInfo

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>

    $Mod = New-InMemoryModule -ModuleName SysInfo

    $ProcessorType = psenum $Mod SYSINFO.PROCESSOR_ARCH UInt16 @{
        PROCESSOR_ARCHITECTURE_INTEL =   0
        PROCESSOR_ARCHITECTURE_MIPS =    1
        PROCESSOR_ARCHITECTURE_ALPHA =   2
        PROCESSOR_ARCHITECTURE_PPC =     3
        PROCESSOR_ARCHITECTURE_SHX =     4
        PROCESSOR_ARCHITECTURE_ARM =     5
        PROCESSOR_ARCHITECTURE_IA64 =    6
        PROCESSOR_ARCHITECTURE_ALPHA64 = 7
        PROCESSOR_ARCHITECTURE_AMD64 =   9
        PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF
    }

    $SYSTEM_INFO = struct $Mod SYSINFO.SYSTEM_INFO @{
        ProcessorArchitecture = field 0 $ProcessorType
        Reserved = field 1 Int16
        PageSize = field 2 Int32
        MinimumApplicationAddress = field 3 IntPtr
        MaximumApplicationAddress = field 4 IntPtr
        ActiveProcessorMask = field 5 IntPtr
        NumberOfProcessors = field 6 Int32
        ProcessorType = field 7 Int32
        AllocationGranularity = field 8 Int32
        ProcessorLevel = field 9 Int16
        ProcessorRevision = field 10 Int16
    }

    $FunctionDefinitions = @(
        (func kernel32 GetSystemInfo ([Void]) @($SYSTEM_INFO.MakeByRefType()))
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32SysInfo'
    $Kernel32 = $Types['kernel32']

    $SysInfo = [Activator]::CreateInstance($SYSTEM_INFO)
    $Kernel32::GetSystemInfo([Ref] $SysInfo)

    $SysInfo
}

function Get-VirtualMemoryInfo {
<#
.SYNOPSIS

A wrapper for kernel32!VirtualQueryEx

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None

.PARAMETER ProcessID

Specifies the process ID.

.PARAMETER ModuleBaseAddress

Specifies the address of the memory to be queried.

.PARAMETER PageSize

Specifies the system page size. Defaults to 0x1000 if one is not
specified.

.EXAMPLE

Get-VirtualMemoryInfo -ProcessID $PID -ModuleBaseAddress 0
#>

    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({Get-Process -Id $_})]
        [Int]
        $ProcessID,

        [Parameter(Position = 1, Mandatory = $True)]
        [IntPtr]
        $ModuleBaseAddress,

        [Int]
        $PageSize = 0x1000
    )

    $Mod = New-InMemoryModule -ModuleName MemUtils

    $MemProtection = psenum $Mod MEMUTIL.MEM_PROTECT Int32 @{
        PAGE_EXECUTE =           0x00000010
        PAGE_EXECUTE_READ =      0x00000020
        PAGE_EXECUTE_READWRITE = 0x00000040
        PAGE_EXECUTE_WRITECOPY = 0x00000080
        PAGE_NOACCESS =          0x00000001
        PAGE_READONLY =          0x00000002
        PAGE_READWRITE =         0x00000004
        PAGE_WRITECOPY =         0x00000008
        PAGE_GUARD =             0x00000100
        PAGE_NOCACHE =           0x00000200
        PAGE_WRITECOMBINE =      0x00000400
    } -Bitfield

    $MemState = psenum $Mod MEMUTIL.MEM_STATE Int32 @{
        MEM_COMMIT =  0x00001000
        MEM_FREE =    0x00010000
        MEM_RESERVE = 0x00002000
    } -Bitfield

    $MemType = psenum $Mod MEMUTIL.MEM_TYPE Int32 @{
        MEM_IMAGE =   0x01000000
        MEM_MAPPED =  0x00040000
        MEM_PRIVATE = 0x00020000
    } -Bitfield

    if ([IntPtr]::Size -eq 4) {
        $MEMORY_BASIC_INFORMATION = struct $Mod MEMUTIL.MEMORY_BASIC_INFORMATION @{
            BaseAddress = field 0 Int32
            AllocationBase = field 1 Int32
            AllocationProtect = field 2 $MemProtection
            RegionSize = field 3 Int32
            State = field 4 $MemState
            Protect = field 5 $MemProtection
            Type = field 6 $MemType
        }
    } else {
        $MEMORY_BASIC_INFORMATION = struct $Mod MEMUTIL.MEMORY_BASIC_INFORMATION @{
            BaseAddress = field 0 Int64
            AllocationBase = field 1 Int64
            AllocationProtect = field 2 $MemProtection
            Alignment1 = field 3 Int32
            RegionSize = field 4 Int64
            State = field 5 $MemState
            Protect = field 6 $MemProtection
            Type = field 7 $MemType
            Alignment2 = field 8 Int32
        }
    }

    $FunctionDefinitions = @(
        (func kernel32 VirtualQueryEx ([Int32]) @([IntPtr], [IntPtr], $MEMORY_BASIC_INFORMATION.MakeByRefType(), [Int]) -SetLastError),
        (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
        (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32MemUtils'
    $Kernel32 = $Types['kernel32']

    # Get handle to the process
    $hProcess = $Kernel32::OpenProcess(0x400, $False, $ProcessID) # PROCESS_QUERY_INFORMATION (0x00000400)

    if (-not $hProcess) {
        throw "Unable to get a process handle for process ID: $ProcessID"
    }

    $MemoryInfo = New-Object $MEMORY_BASIC_INFORMATION
    $BytesRead = $Kernel32::VirtualQueryEx($hProcess, $ModuleBaseAddress, [Ref] $MemoryInfo, $PageSize)

    $null = $Kernel32::CloseHandle($hProcess)

    $Fields = @{
        BaseAddress = $MemoryInfo.BaseAddress
        AllocationBase = $MemoryInfo.AllocationBase
        AllocationProtect = $MemoryInfo.AllocationProtect
        RegionSize = $MemoryInfo.RegionSize
        State = $MemoryInfo.State
        Protect = $MemoryInfo.Protect
        Type = $MemoryInfo.Type
    }

    $Result = New-Object PSObject -Property $Fields
    $Result.PSObject.TypeNames.Insert(0, 'MEM.INFO')

    $Result
}

filter Get-ProcessMemoryInfo {
<#
.SYNOPSIS

Retrieve virtual memory information for every unique set of pages in
user memory. This function is similar to the !vadump WinDbg command.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
                       Get-SystemInfo
                       Get-VirtualMemoryInfo
Optional Dependencies: None

.PARAMETER ProcessID

Specifies the process ID.

.EXAMPLE

Get-ProcessMemoryInfo -ProcessID $PID
#>

    Param (
        [Parameter(ParameterSetName = 'InMemory', Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Id')]
        [ValidateScript({Get-Process -Id $_})]
        [Int]
        $ProcessID
    )

    $SysInfo = Get-SystemInfo

    $MemoryInfo = Get-VirtualMemoryInfo -ProcessID $ProcessID -ModuleBaseAddress ([IntPtr]::Zero) -PageSize $SysInfo.PageSize

    $MemoryInfo

    while (($MemoryInfo.BaseAddress + $MemoryInfo.RegionSize) -lt $SysInfo.MaximumApplicationAddress) {
        $BaseAllocation = [IntPtr] ($MemoryInfo.BaseAddress + $MemoryInfo.RegionSize)
        $MemoryInfo = Get-VirtualMemoryInfo -ProcessID $ProcessID -ModuleBaseAddress $BaseAllocation -PageSize $SysInfo.PageSize
        
        if ($MemoryInfo.State -eq 0) { break }
        $MemoryInfo
    }
}

# -------- PSReflect -------------
# http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func
 
.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion Helper Functions


##################     MAIN     ##################

Write-Verbose "Starting Scan"

# Scan Start Time:
$Scan_start = Get-date


# RUN TESTS AND BUILD HOST OBJECT 

# Get Host Info
$HostInfo = Get-HostInfo
try { $IPs = ([System.Net.Dns]::GetHostAddresses($HostInfo.DNSHostname)).IPAddressToString } catch { $IPs = $null }

# Build HostObject Metadata
Write-Verbose "Building HostObject"
$HostObjProperties = @{
	ObjectName			= $HostInfo.Name + "_HostObject"
	ObjGUID				= [Guid]::NewGuid().ToString()
	Version				= $Version
	ObjectType			= "psHunt_HostObject"
	Processed			= $False
	DateProcessed		= $Null
	SurveyStart			= $Scan_start
	IPAddresses			= $IPs
	Hostname			= $HostInfo.DNSHostname
}

$HostObject = New-Object PSObject -Property $HostObjProperties
$HostObject.PSObject.TypeNames.Insert(0, 'PSHunt_HostObject')

# Running Tests and adding to HostObject 
Write-Verbose "Running Tests and adding to HostObject"
$TestTimes = New-Object PSObject -Property @{
	SurveyStart = $Scan_start
}

$HostObject | Add-Member -type NoteProperty -Name HostInfo 			-Value $HostInfo

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name ProcessList 		-Value (Get-Processes)
$TestTimes  | Add-Member -type NoteProperty -Name ProcessList 		-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name Netstat 			-Value (Get-Netstat)
$TestTimes  | Add-Member -type NoteProperty -Name Netstat 			-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name DisplayDNS 			-Value (Get-DisplayDNS)
$TestTimes  | Add-Member -type NoteProperty -Name DisplayDNS 			-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
# Just do some core processes that will likely be injected as this function is extremely slow on some systems.  Might go to WorkingSet only in future.
$HostObject | Add-Member -type NoteProperty -Name InjectedModules 	-Value (Get-Process | where { $_.Path -match "WINDOWS|Microsoft|Chrome|iexplorer|firefox" } | Get-MemoryInjects)
$TestTimes  | Add-Member -type NoteProperty -Name InjectedModules 	-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name ModuleList		-Value (Get-Modules)
$TestTimes  | Add-Member -type NoteProperty -Name ModuleList 		-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name DriverList 		-Value (Get-Drivers)
$TestTimes  | Add-Member -type NoteProperty -Name DriverList 		-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date 
$HostObject | Add-Member -type NoteProperty -Name Autoruns 			-Value (Get-PSAutorun -All -CheckSignatures)
$TestTimes  | Add-Member -type NoteProperty -Name Autoruns 			-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
$HostObject | Add-Member -type NoteProperty -Name Accounts 			-Value (Get-AccountInfo)
$TestTimes  | Add-Member -type NoteProperty -Name Accounts 			-Value ((Get-Date)-$testtime).TotalSeconds

$testtime = Get-Date
# Misc tests
$HostObject | Add-Member -type NoteProperty -Name Disks 			-Value (Get-DiskInfo)
$HostObject | Add-Member -type NoteProperty -Name NetworkConfig		-Value (Get-NetworkConfig)
$HostObject | Add-Member -type NoteProperty -Name Pipes 			-Value (Get-Pipes)
$HostObject | Add-Member -type NoteProperty -Name OldestEventlog	-Value (Get-OldestLogs)
$HostObject | Add-Member -type NoteProperty -Name FirewallRules		-Value (Get-FirewallRules)
$HostObject | Add-Member -type NoteProperty -Name Misc				-Value (Get-InterestingStuff)
$HostObject | Add-Member -type NoteProperty -Name InstalledApps		-Value (Get-InstalledApps)
$TestTimes  | Add-Member -type NoteProperty -Name Misc	 			-Value ((Get-Date)-$testtime).TotalSeconds


# Add scan metadata
$Scan_complete = Get-date
$HostObject  | Add-Member -type NoteProperty -Name SurveyStop -Value $Scan_complete
$TestTimes  | Add-Member -type NoteProperty -Name SurveyStop -Value $Scan_complete
$TestTimes  | Add-Member -type NoteProperty -Name SurveyRunTime  -Value ($Scan_complete - $Scan_start).totalseconds
$HostObject | Add-Member -type NoteProperty -Name TestTimes -Value $TestTimes

# Return Results:

Switch ($ReturnType) {
	"NoDrop" { return $HostObject }
	"DropToDisk" {
		# Drop to Disk
		# Export Object to XML
		Write-Verbose "Exporting HostObject to $OutPath"
		$HostObject | Export-CliXML $OutPath -encoding 'UTF8' -force
	}
	"HTTPPostback" {
		# Post to Web Server
		Write-Verbose "Posting results to web server"
		# $ReturnAddress = "http://www.YourDomainName.com/ClientFiles/"
		$destinationFilePath = $ReturnAddress + $SurveyOut
		$wc = New-Object System.Net.WebClient
		if ($WebCredentials) { 
			$wc.Credentials = $WebCredentials.GetNetworkCredentials() 
		} else {
			$wc.UseDefaultCredentials = $true
		}
		try { 
			$wc.UploadFile($destinationFilePath, "PUT", $OutPath)
		} 
		catch {
			Write-Warning "Error posting to web server, dropping to disk"
			# Export Object to XML
			Write-Verbose "Exporting HostObject!"
			$HostObject | Export-CliXML $OutPath -encoding 'UTF8' -force
		} 
		finally {
			$wc.Dispose()
		}	
	}
	"FTPPostback" {
		# Post to FTP Server
		Write-Verbose "Posting results to ftp server"
		# $ReturnAddress = "ftp://www.YourDomainName.com/ClientFiles/"
		$destinationFilePath = $ReturnAddress + $SurveyOut
		$uri = New-Object System.Uri($ftpAddress+$SurveyOut) 
		$wc = New-Object System.Net.WebClient
		if ($WebCredentials) { 
			$wc.Credentials = $WebCredentials.GetNetworkCredentials() 
		} else {
			$wc.UseDefaultCredentials = $true
		}
		try { 
			$wc.UploadFile($uri, $OutPath) 
		} 
		catch {
			Write-Warning "Error posting to FTP server, dropping to disk"
			# Export Object to XML
			Write-Verbose "Exporting HostObject!"
			$HostObject | Export-CliXML $OutPath -encoding 'UTF8' -force
		} 
		finally {
			$wc.Dispose()
		}
	}
} 

Write-Verbose "Scan Complete!"

# Cleanup temp files and delete the survey script (if not running interactively)
if (($ScriptPath) -AND ($ScriptDir -match "^C:\\Windows*")) { 
	Remove-Item $ScriptPath
	#have to do this or it sometimes freezes
	[System.Diagnostics.Process]::GetCurrentProcess().Kill()
}
