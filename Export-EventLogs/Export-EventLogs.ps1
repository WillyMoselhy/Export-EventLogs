# v-waalmo@microsoft.com amended this script to allow it to run as stand alone by copying the needed functions from other scritps
# Running it alone will export all Event Logs on the system to a folder named EventLogs as EVTX, CSV, and TXT
# Date: 2019-02-19 - Last Edit: 2019-02-20

#************************************************
# TS_GetEvents.ps1
# Version 2.3.5
# Date: 05-13-2013 - Last_Edit: 2018-06-16
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is used to export machine event logs in different formats, such as EVT(X), CSV and TXT
#************************************************

PARAM($EventLogNames="", # v-waalmo: This was "AllWMI" in original version
	  $OutputFormats="",
	  $ExclusionList="", 
	  $Days="", 
	  $EventLogAdvisorAlertXMLs ="",
	  $SectionDescription="Event Logs",
	  $Prefix=$null,
	  $Suffix=$null,
	  $Query=$Null,
	  $After,
	  $Before,
	  [switch] $DisableRootCauseDetection)

#region: v-waalmo - Functions and variables added from other scripts to make this one stand alone
	$ComputerName = $Env:computername
	$OSVersion = [Environment]::OSVersion.Version
	Function Write-DiagProgress ($Activity, $Status)
	{
		trap [Exception] 
		{
			#Ignore any error like - when the file is locked
			continue
		}
		
		#On ServerCore, $Activity go to WriteDiagProgress.txt. Discart $status
		if ($Activity -ne $null) 
		{
			$Activity + ": " + $Status | Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8" -ErrorAction Continue
			"   Write-DiagProgress: " + $Activity + ": " + $Status
		} else {
		 ""	| Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8"
		}
	}	
	Function RunCMD([string]$commandToRun, 
	$filesToCollect = $null, 
	[string]$fileDescription="", 
	[string]$sectionDescription="", 
	[boolean]$collectFiles=$true,
	[switch]$useSystemDiagnosticsObject,
	[string]$Verbosity="Informational",
	[switch]$NoFileExtensionsOnDescription,
	[switch]$BackgroundExecution,
	[boolean]$RenameOutput=$false,
	[switch]$DirectCommand,
	[Scriptblock] $PostProcessingScriptBlock)
	{

	trap [Exception] 
	{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[RunCMD (commandToRun = $commandToRun) (filesToCollect = $filesToCollect) (fileDescription $fileDescription) (sectionDescription = $sectionDescription) (collectFiles $collectFiles)]" -InvokeInfo $MyInvocation
	$Error.Clear()
	continue
	}

	if ($useSystemDiagnosticsObject.IsPresent) {
	$StringToAdd = " (Via System.Diagnostics.Process)"
	} else {
	$StringToAdd = ""
	}

	if ($filesToCollect -eq $null)
	{
	$collectFiles = $false
	}

	if (($BackgroundExecution.IsPresent) -and ($collectFiles -eq $false))
	{
	"[RunCMD] Warning: Background execution will be ignored since -collectFiles is false" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	}

	if ($BackgroundExecution.IsPresent)
	{
	$StringToAdd += " (Background Execution)"
	}
	$StringToAdd += " (Collect Files: $collectFiles)"

	"[RunCMD] Running Command" + $StringToAdd + ":`r`n `r`n                      $commandToRun`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat

	# A note: if CollectFiles is set to False, background processing is not allowed
	# This is to avoid problems where multiple background commands write to the same file
	if (($BackgroundExecution.IsPresent -eq $false) -or ($collectFiles -eq $false))
	{    
	"--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader

	if ($useSystemDiagnosticsObject.IsPresent) 
	{
	if ($DirectCommand.IsPresent)
	{
	if ($commandToRun.StartsWith("`""))
	{
		$ProcessName = $commandToRun.Split("`"")[1]
		$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
	} 
	elseif ($commandToRun.Contains(".exe"))
	# 2. No quote found - try to find a .exe on $commandToRun
	{
		$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
		$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
	}
	else
	{
		$ProcessName = "cmd.exe" 
		$Arguments = "/c `"" + $commandToRun + "`""
	}
	$process = ProcessCreate -Process $ProcessName -Arguments $Arguments
	}
	else
	{
	$process = ProcessCreate -Process "cmd.exe" -Arguments ("/s /c `"" + $commandToRun + "`"")
	}
	$process.WaitForExit()
	$StdoutOutput = $process.StandardOutput.ReadToEnd() 
	if ($StdoutOutput -ne $null)
	{
	($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
	}
	else
	{
	'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
	}
	$ProcessExitCode = $process.ExitCode
	if ($ProcessExitCode -ne 0) 
	{
	"[RunCMD] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode)  + " when running command line:`r`n             " + $commandToRun | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
	$ProcessStdError = $process.StandardError.ReadToEnd()
	if ($ProcessStdError -ne $null)
	{
		"--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
	}
	}
	} 
	else 
	{
	if ($commandToRun -ne $null)
	{
	$StdoutOutput = Invoke-Expression $commandToRun
	if ($StdoutOutput -ne $null)
	{
		($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
	}
	else
	{
		'(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
	}
	$ProcessExitCode = $LastExitCode
	if ($LastExitCode -gt 0)
	{
		"[RunCMD] Warning: Process exited with error code " + ("0x{0:X}" -f $ProcessExitCode) | writeto-stdout -InvokeInfo $MyInvocation -Color 'DarkYellow'
	}
	}
	else
	{
	'[RunCMD] Error: a null -commandToRun argument was sent to RunCMD' | writeto-stdout -InvokeInfo $MyInvocation -IsError
	$ProcessExitCode = 99
	}
	}

	"--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat

	if ($collectFiles -eq $true) 
	{    
	"[RunCMD] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
	if ($noFileExtensionsOnDescription.isPresent)
	{
	CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -noFileExtensionsOnDescription -renameOutput $renameOutput -InvokeInfo $MyInvocation
	} else {
	CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
	}
	}
	#RunCMD returns exit code only if -UseSystemDiagnosticsObject is used
	if ($useSystemDiagnosticsObject.IsPresent)
	{
	return $ProcessExitCode
	}
	} 
	else 
	{     #Background Process
	# Need to separate process name from $commandToRun:
	# 1. Try to identify a quote:
	if ($commandToRun.StartsWith("`""))
	{
	$ProcessName = $commandToRun.Split("`"")[1]
	$Arguments = ($commandToRun.Split("`"",3)[2]).Trim()
	} 
	elseif ($commandToRun.Contains(".exe"))
	# 2. No quote found - try to find a .exe on $commandToRun
	{
	$ProcessName = $commandToRun.Substring(0,$commandToRun.IndexOf(".exe")+4)
	$Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe")+5, $commandToRun.Length - $commandToRun.IndexOf(".exe")-5)
	}
	else
	{
	$ProcessName = "cmd.exe" 
	$Arguments = "/c `"" + $commandToRun + "`""
	}
	if ($noFileExtensionsOnDescription.isPresent)
	{
	$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -CollectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock 
	}
	else 
	{
	$process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -noFileExtensionsOnDescription -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock
	}
	}

	}

	Filter WriteTo-ErrorDebugReport
	(
	[string] $ScriptErrorText, 
	[System.Management.Automation.ErrorRecord] $ErrorRecord = $null,
	[System.Management.Automation.InvocationInfo] $InvokeInfo = $null,
	[switch] $SkipWriteToStdout
	)
	{

	trap [Exception] 
	{
	$ExInvokeInfo = $_.Exception.ErrorRecord.InvocationInfo
	if ($ExInvokeInfo -ne $null)
	{
	$line = ($_.Exception.ErrorRecord.InvocationInfo.Line).Trim()
	}
	else
	{
	$Line = ($_.InvocationInfo.Line).Trim()
	}

	if (-not ($SkipWriteToStdout.IsPresent))
	{
	"[WriteTo-ErrorDebugReport] Error: " + $_.Exception.Message + " [" + $Line + "].`r`n" + $_.StackTrace | WriteTo-StdOut
	}
	continue
	}

	if (($ScriptErrorText.Length -eq 0) -and ($ErrorRecord -eq $null)) {$ScriptErrorText=$_}

	if (($ErrorRecord -ne $null) -and ($InvokeInfo -eq $null))
	{
	if ($ErrorRecord.InvocationInfo -ne $null)
	{
	$InvokeInfo = $ErrorRecord.InvocationInfo
	}
	elseif ($ErrorRecord.Exception.ErrorRecord.InvocationInfo -ne $null)
	{
	$InvokeInfo = $ErrorRecord.Exception.ErrorRecord.InvocationInfo
	}
	if ($InvokeInfo -eq $null)
	{
	$InvokeInfo = $MyInvocation
	}
	}
	elseif ($InvokeInfo -eq $null)
	{
	$InvokeInfo = $MyInvocation
	}

	$Error_Summary = New-Object PSObject

	if (($InvokeInfo.ScriptName -ne $null) -and ($InvokeInfo.ScriptName.Length -gt 0))
	{
	$ScriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
	}
	elseif (($InvokeInfo.InvocationName -ne $null) -and ($InvokeInfo.InvocationName.Length -gt 1))
	{
	$ScriptName = $InvokeInfo.InvocationName
	}
	elseif ($MyInvocation.ScriptName -ne $null)
	{
	$ScriptName = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
	}

	$Error_Summary_TXT = @()
	if (-not ([string]::IsNullOrEmpty($ScriptName)))
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Script" -Value $ScriptName 
	}

	if ($InvokeInfo.Line -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value ($InvokeInfo.Line).Trim()
	$Error_Summary_TXT += "Command: [" + ($InvokeInfo.Line).Trim() + "]"
	}
	elseif ($InvokeInfo.MyCommand -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value $InvokeInfo.MyCommand.Name
	$Error_Summary_TXT += "Command: [" + $InvokeInfo.MyCommand.Name + "]"
	}

	if ($InvokeInfo.ScriptLineNumber -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Line Number" -Value $InvokeInfo.ScriptLineNumber
	}

	if ($InvokeInfo.OffsetInLine -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Column  Number" -Value $InvokeInfo.OffsetInLine
	}

	if (-not ([string]::IsNullOrEmpty($ScriptErrorText)))
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Additional Info" -Value $ScriptErrorText
	}

	if ($ErrorRecord.Exception.Message -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Error Text" -Value $ErrorRecord.Exception.Message
	$Error_Summary_TXT += "Error Text: " + $ErrorRecord.Exception.Message
	}
	if($ErrorRecord.ScriptStackTrace -ne $null)
	{
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Stack Trace" -Value $ErrorRecord.ScriptStackTrace
	}

	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Custom Error" -Value "Yes"

	if ($ScriptName.Length -gt 0)
	{
	$ScriptDisplay = "[$ScriptName]"
	}

	$Error_Summary | ConvertTo-Xml | update-diagreport -id ("ScriptError_" + (Get-Random)) -name "Script Error $ScriptDisplay" -verbosity "Debug"
	if (-not ($SkipWriteToStdout.IsPresent))
	{
	"[WriteTo-ErrorDebugReport] An error was logged to Debug Report: " + [string]::Join(" / ", $Error_Summary_TXT) | WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat -IsError
	}
	$Error_Summary | fl * | Out-String | WriteTo-StdOut -DebugOnly -IsError
	}

	function WriteTo-StdOut
	{
		param (
			$ObjectToAdd,
			[switch]$ShortFormat,
			[switch]$IsError,
			$Color,
			[switch]$DebugOnly,
			[switch]$PassThru,
			[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation,
			[string]$AdditionalFileName = $null,
			[switch]$noHeader)
		BEGIN
		{
			$WhatToWrite = @()
			if ($ObjectToAdd -ne  $null)
			{
				$WhatToWrite  += $ObjectToAdd
			} 
			
			if(($Debug) -and ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host"))
			{
				if($Color -eq $null)
				{
					$Color = $Host.UI.RawUI.ForegroundColor
				}
				elseif($Color -isnot [ConsoleColor])
				{
					$Color = [Enum]::Parse([ConsoleColor],$Color)
				}
				$scriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
			}
			
			$ShortFormat = $ShortFormat -or $global:ForceShortFormat
		}
		PROCESS
		{
			if ($_ -ne $null)
			{
				if ($_.GetType().Name -ne "FormatEndData") 
				{
					$WhatToWrite += $_ | Out-String 
				}
				else 
				{
					$WhatToWrite = "Object not correctly formatted. The object of type Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData is not valid or not in the correct sequence."
				}
			}
		}
		END
		{
			if($ShortFormat)
			{
				$separator = " "
			}
			else
			{
				$separator = "`r`n"
			}
			$WhatToWrite = [string]::Join($separator,$WhatToWrite)
			while($WhatToWrite.EndsWith("`r`n"))
			{
				$WhatToWrite = $WhatToWrite.Substring(0,$WhatToWrite.Length-2)
			}
			if(($Debug) -and ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host"))
			{
				$output = "[$([DateTime]::Now.ToString(`"s`"))] [$($scriptName):$($MyInvocation.ScriptLineNumber)]: $WhatToWrite"
	
				if($IsError.Ispresent)
				{
					$Host.UI.WriteErrorLine($output)
				}
				else
				{
					if($Color -eq $null){$Color = $Host.UI.RawUI.ForegroundColor}
					$output | Write-Host -ForegroundColor $Color
				}
				if($global:DebugOutLog -eq $null)
				{
					$global:DebugOutLog = Join-Path $Env:TEMP "$([Guid]::NewGuid().ToString(`"n`")).txt"
				}
				$output | Out-File -FilePath $global:DebugOutLog -Append -Force 
			}
			elseif(-not $DebugOnly)
			{
				[System.Threading.Monitor]::Enter($global:m_WriteCriticalSection)
				
				trap [Exception] 
				{
					WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
					continue
				}
				Trap [System.IO.IOException]
				{
					# An exection in this location indicates either that the file is in-use or user do not have permissions. Wait .5 seconds. Try again
					sleep -Milliseconds 500
					WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
					continue
				}
				
				if($ShortFormat)
				{
					if ($NoHeader.IsPresent)
					{
						$WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
						 if ($AdditionalFileName.Length -gt 0)
						 {
							 $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
						 }
					}
					else
					{
						 "[" + (Get-Date -Format "T") + " " + $ComputerName + " - " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " - " + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
						 if ($AdditionalFileName.Length -gt 0)
						 {
							 "[" + (Get-Date -Format "T") + " " + $ComputerName + " - " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " - " + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
						 }
					}
				}
				else
				{
					if ($NoHeader.IsPresent)
					{
						 "`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
						 if ($AdditionalFileName.Length -gt 0)
						 {
							 "`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
						 }
					}
					else
					{
						 "`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
						 if ($AdditionalFileName.Length -gt 0)
						 {
							 "`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
						 }
					}
				}
				[System.Threading.Monitor]::Exit($global:m_WriteCriticalSection)
	
			}
			if($PassThru)
			{
				return $WhatToWrite
			}
		}
	}

#endregion

Import-LocalizedData -BindingVariable GetEventsStrings


Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status $GetEventsStrings.ID_ExportingLogs

if ($EventLogNames -eq ""){# v-waalmo: Show list of events to select from
	$EventLogNames = wevtutil.exe el | Out-GridView -Title "Select event logs to export" -OutputMode Multiple
}


$DisplayToAdd = ''
if (-not (Test-Path($PWD.Path + "\EventLogs"))) {[void]( md ($PWD.Path + "\EventLogs")) }
$OutputPath = $PWD.Path + "\EventLogs"

if (($OSVersion.Major -lt 6) -and ($EventLogNames -eq "AllEvents")) #Pre-WinVista
{
	$EventLogNames = "AllWMI"
}

if ($Days -ne "")
{
	$Days = "/days:$Days"
	$DisplayToAdd = " ($Days days)"
	
	if ($Query -ne $null) {"WARNING: Query argument cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -IsError -ShortFormat -InvokeInfo $MyInvocation}
	if (($After -ne $null) -or ($Before -ne $null) ) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif ($Query -ne $null)
{
	$Query = "`"/query:$Query`""
	if (($After -ne $null) -or ($Before -ne $null)) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Query and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif (($After -ne $null) -and ($Before -ne $null) -and ($Before -le $After))
{
	"WARNING: -Before argument contains [$Before] and cannot be earlier than -After argument: [$After] and therefore it will ignored." | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
}

if ((($After -ne $null) -or ($Before -ne $null)) -and ($OSVersion.Major -ge 6))
{
	if (($After -ne $null) -and (($After -as [DateTime]) -eq $null))
	{
		"-After argument type is [" + $After.GetType() + "] and contains value [$After]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$After = $null
	}
	
	if (($Before -ne $null) -and (($Before -as [DateTime]) -eq $null))
	{
		"-Before argument type is [" + $Before.GetType() + "] and contains value [$Before]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$Before = $null
	}
	
	if (($After -ne $null) -or ($Before -ne $null))
	{
		$DisplayToAdd = " (Filtered)"
		$TimeRange = @()

		if ($Before -ne $null)
		{
			$BeforeLogString = "[Before: $Before $($Before.Kind.ToString())]"
			if ($Before.Kind -ne [System.DateTimeKind]::Utc)
			{
				$Before += [System.TimeZoneInfo]::ConvertTimeToUtc($Before)
			}
			$TimeRange += "@SystemTime <= '" + $Before.ToString("o") + "'"
		}
		
		if ($After -ne $null)
		{
			$AfterLogString = "[After: $After $($After.Kind.ToString())]"
			if ($After.Kind -ne [System.DateTimeKind]::Utc)
			{
				$After += [System.TimeZoneInfo]::ConvertTimeToUtc($After)
			}
			$TimeRange += "@SystemTime >= '" + $After.ToString("o") + "'"
		}

		"-Before and/ or -After arguments to TS_GetEvents were used: $BeforeLogString $AfterLogString" | WriteTo-StdOut

		$Query = "*[System[TimeCreated[" + [string]::Join(" and ", $TimeRange) + "]]]"
		$Query = "`"/query:$Query`""
	}
}
elseif ((($After -ne $null) -or ($Before -ne $null)) -and ($OSVersion.Major -lt 6))
{
	"WARNING: Arguments -After or -Before arguments are supported only on Windows Vista or newer Operating Systems and therefore it will ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
	$Before = $null
}

switch ($EventLogNames)	
{
	"AllEvents" 
	{
		#Commented line below since Get-WinEvent requires .NET Framework 3.5 - which is not always installed on server media
		#$EventLogNames = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName
		$EventLogNames = wevtutil.exe el
	}
	"AllWMI" 
	{
		$EventLogList = Get-EventLog -List | Where-Object {$_.Entries.Count -gt 0} | Select-Object @{Name="LogName"; Expression={$_.Log}}
		$EventLogNames = @()
		$EventLogList | ForEach-Object {$EventLogNames += $_.LogName}
	}
}

if ($OutputFormats -eq "") 
{
	$OutputFormatCMD = "/TXT /CSV /evtx /evt"
} 
else 
{
	ForEach ($OutputFormat in $OutputFormats) 
	{
		$OutputFormatCMD += "/" + $OutputFormat + " "
	}
}

$EventLogAdvisorXMLCMD = ""

if (($EventLogAdvisorAlertXMLs -ne "") -or ($Global:EventLogAdvisorAlertXML -ne $null))
{
	$EventLogAdvisorXMLFilename = Join-Path -Path $PWD.Path -ChildPath "EventLogAdvisorAlerts.XML"
	"<?xml version='1.0'?>" | Out-File $EventLogAdvisorXMLFilename
	
	if ($EventLogAdvisorAlertXMLs -ne "")
	{
		ForEach ($EventLogAdvisorXML in $EventLogAdvisorAlertXMLs) 
		{
			#Save Alerts to disk, then, use file as command line for GetEvents script
			$EventLogAdvisorXML | Out-File $EventLogAdvisorXMLFilename -append
		}
	}
	
	if ($Global:EventLogAdvisorAlertXML -ne $null)
	{
		if (Test-Path $EventLogAdvisorXMLFilename)
		{
			"[GenerateEventLogAdvisorXML] $EventLogAdvisorXMLFilename already exists. Merging content."
			[xml] $EventLogAdvisorXML = Get-Content $EventLogAdvisorXMLFilename
			
			ForEach ($GlobalSectionNode in $Global:EventLogAdvisorAlertXML.SelectNodes("/Alerts/Section"))
			{
			
				$SectionName = $GlobalSectionNode.SectionName
				$SectionElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[SectionName = `'$SectionName`']")
				if ($SectionElement -eq $null)
				{
					$SectionElement = $EventLogAdvisorXML.CreateElement("Section")						
					$X = $EventLogAdvisorXML.SelectSingleNode('Alerts').AppendChild($SectionElement)
					
					$SectionNameElement = $EventLogAdvisorXML.CreateElement("SectionName")
					$X = $SectionNameElement.set_InnerText($SectionName)						
					$X = $SectionElement.AppendChild($SectionNameElement)
					
					$SectionPriorityElement = $EventLogAdvisorXML.CreateElement("SectionPriority")
					$X = $SectionPriorityElement.set_InnerText(30)
					$X = $SectionElement.AppendChild($SectionPriorityElement)
				}
				
				ForEach ($GlobalSectionAlertNode in $GlobalSectionNode.SelectNodes("Alert"))
				{
					$EventLogName = $GlobalSectionAlertNode.EventLog
					$EventLogSource = $GlobalSectionAlertNode.Source
					$EventLogId = $GlobalSectionAlertNode.ID
					
					$ExistingAlertElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[Alert[(EventLog = `'$EventLogName`') and (Source = `'$EventLogSource`') and (ID = `'$EventLogId`')]]")

					if ($ExistingAlertElement -eq $null)
					{
						$AlertElement = $EventLogAdvisorXML.CreateElement("Alert")
						$X = $AlertElement.Set_InnerXML($GlobalSectionAlertNode.Get_InnerXML())
						$X = $SectionElement.AppendChild($AlertElement)
					}
					else
					{
						"WARNING: An alert for event log [$EventLogName], Event ID [$EventLogId], Source [$EventLogSource] was already been queued by another script." | WriteTo-StdOut -ShortFormat
					}
				}
			}
			
			$EventLogAdvisorXML.Save($EventLogAdvisorXMLFilename)
				
		}
		else
		{
			$Global:EventLogAdvisorAlertXML.Save($EventLogAdvisorXMLFilename)
		}
	}
	
	$EventLogAdvisorXMLCMD = "/AlertXML:$EventLogAdvisorXMLFilename /GenerateScriptedDiagXMLAlerts "
}
	
if ($SectionDescription -eq "") 
{
	$SectionDescription = $GetEventsStrings.ID_EventLogFiles
}

if ($Prefix -ne $null)
{
	$Prefix = "/prefix:`"" + $ComputerName + "_evt_" + $Prefix + "`""
}

if ($Suffix -ne $null)
{
	$Suffix = "/suffix:`"" + $Suffix + "`""
}

ForEach ($EventLogName in $EventLogNames) 
{
    if ($ExclusionList -notcontains $EventLogName) 
	{
		$ExportingString = $GetEventsStrings.ID_ExportingLogs
    	Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status ($ExportingString + ": " + $EventLogName)
    	$CommandToExecute = "cscript.exe //E:vbscript GetEvents.VBS `"$EventLogName`" /channel $Days $OutputFormatCMD $EventLogAdvisorXMLCMD `"$OutputPath`" /noextended $Query $Prefix $Suffix"
		$OutputFiles = $OutputPath + "\" + $Computername + "_evt_*.*"
		$FileDescription = $EventLogName.ToString() + $DisplayToAdd

		RunCmD -commandToRun $CommandToExecute -sectionDescription $SectionDescription -filesToCollect $OutputFiles -fileDescription $FileDescription

		<# v-waalmo removed the following lines (I don't know why they exist)
		$EventLogFiles = Get-ChildItem $OutputFiles
		if ($EventLogFiles -ne $null) 
		{
    		$EventLogFiles | Remove-Item
		}
		#>
    }
}

$EventLogAlertXMLFileName = $Computername + "_EventLogAlerts.XML"

if (($DisableRootCauseDetection.IsPresent -ne $true) -and (test-path $EventLogAlertXMLFileName)) 
{	
	[xml] $XMLDoc = Get-Content -Path $EventLogAlertXMLFileName
	if($XMLDoc -ne $null)
	{
		$Processed = $XMLDoc.SelectSingleNode("//Processed").InnerXML
	}
	
	if($Processed -eq $null)
	{
		#Check if there is any node that does not contain SkipRootCauseDetection. In this case, set root cause detected to 'true'
		if ($XMLDoc.SelectSingleNode("//Object[not(Property[@Name=`"SkipRootCauseDetection`"])]") -eq $null)
		{
			Update-DiagRootCause -id RC_GetEvents -Detected $true
			
			if($XMLDoc -ne $null)
			{
				[System.Xml.XmlElement] $rootElement=$XMLDoc.SelectSingleNode("//Root")
				[System.Xml.XmlElement] $element = $XMLDoc.CreateElement("Processed")
				$element.innerXML = "True"
				$rootElement.AppendChild($element)
				$XMLDoc.Save($EventLogAlertXMLFileName)	
			}
		}
	}
}
