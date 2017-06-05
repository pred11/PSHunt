
function Write-Log {
	Param(	
		[string]$Target, 
		[String]$LogPath, 
		[string]$Msg, 
		[int]$n
	)
	$Time = get-date -format "yyyy-MM-dd hh:mm:ss:ms"
	if ($Msg -match "ERROR") {
		$a = (Get-Host).PrivateData
		$temp = $a.VerboseForegroundColor
		$a.VerboseForegroundColor = "red"
		Write-Verbose "($n): $Msg"	
		$a.VerboseForegroundColor = $temp
	} elseif ($Msg -like "*SUCCESS*") {
	    $a = (Get-Host).PrivateData
		$temp = $a.VerboseForegroundColor
		$a.VerboseForegroundColor = "green"
		Write-Verbose "($n): $Msg"	
		$a.VerboseForegroundColor = $temp
	} else {
		Write-Verbose "($n): $Msg"	
	}
	"$Time, $Target, " + $Msg | Out-File -Encoding 'ASCII' -Append $LogPath
}
