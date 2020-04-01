<#===========================================================================================================================
 Script Name: Set-RestartComputers.ps1
 Description: Restarts Bulk computers, and attempts to ping for x minutes and number of attempts and send email about Service and Reboot status.
      Inputs: Remote ComputerName in text or AD computers in get-adcomputer
     Outputs: Computers that are restarted
       Notes: Check how to input computer names
      Author: Allenage.com
Date Created: 22/10/2017
     Credits: Richard Wright for loop pinging
Last Revised: 15/11/2017
=============================================================================================================================
Instructions
------------
$computers=Get-ADComputer -Filter {OperatingSystem -notlike "*Server*" }  |select -exp name 

# To Reboot all The Workstations
$computers=Get-ADComputer -Filter {OperatingSystem -like "*Server*" }  |select -exp name 

# To Reboot all The Computers located in OU
$computers=Get-ADComputer -Filter * -SearchBase "CN=Office, DC=contoso, DC=com"  |select -exp name 

To Reboot all the computers from Text file, note the text file should contain only computername by line
Example:
Computer1
Computer2

$computers= Get-Content c:\list.txt

To get your own computername list and exclude some computers 
Open Powershell and export the list of computers.

Get-ADComputer -Filter *  |select -exp name|out-file c:\list.txt
Also you can use any filter mention above

#****** enter email details at line 46 ******** ##


################################################################***** ##################################################################>
$computers= Get-content c:\scripts\list.txt

$rebooted="c:\scripts\restarted.txt"
$rebootfail="c:\scripts\failtoreboot.txt"
$servicefail="c:\scripts\servicefail.html"
$OutputFile = "c:\scripts\Output.htm"
$Offline="C:\scripts\offline.txt"

## This is Line 46, enter email details here

$emailto="admin@domain.com"
$emailFrom ="Alert@domain.com"
$smtpserver ="mail@domain.com"

ForEach ($computer in $computers)
{if((Test-Connection -Cn $computer -BufferSize 16 -Count 1 -ea 0 -quiet)){
       Try {
Restart-computer -ComputerName $computer  -force -ErrorAction stop
Write-Host "Restarting $computer" -f green 
$($computer)|Out-File $rebooted -append
}
Catch {
[system.exception]
Write-output "Failed to restart $($computer) `n$error[0]" |Out-File $rebootfail -append

}
}
else {
     Write-Host "cannot reach $($computer) offline" -BackgroundColor red
     Write-output "$($computer)"|Out-File $Offline -append
     }
     }  
     
     ## wait for 2 Minutes to check if the computer is coming back!
Start-Sleep -Seconds 120 
$ComputerNameArray = Get-Content -Path $rebooted
[int]$SleepTimer = "1" #minutes to attempt after
[int]$Attempts = "2"


foreach($ComputerName in $ComputerNameArray) {
    $AttemptsCounter = 0
    $RemainingAttempts = $Attempts - $AttemptsCounter

    Write-Host "Testing to see if ""$ComputerName"" is coming online..."

    while($RemainingAttempts -gt 0) {
        if(Test-Connection -ComputerName $ComputerName -Quiet -Count 1) {
            Write-Host """$ComputerName""" -BackgroundColor Green  -NoNewline
            Write-Host " Is coming online...Skipping to offline one's"
            break
        } else {
            Write-Host """$ComputerName""" -BackgroundColor Red  -NoNewline
            Write-Host " is Offline" -BackgroundColor Red -ForegroundColor Black -NoNewline
            Write-Host ". Pausing for $SleepTimer minutes. Remaining attempts: $($RemainingAttempts - 1)"
            Start-Sleep -Seconds ($SleepTimer * 60)
            $RemainingAttempts--
        }
    }

    if($RemainingAttempts -eq 0) {
        Write-Host "Maximum number of attempts reached" 
    }
}


########## ***** get Uptime and online status ****** ############

$ServerList = Get-Content "$rebooted"

$Result = @()
Foreach($ServerName in $ServerList)
{
	$pingStatus = Test-Connection -ComputerName $servername -Count 2 -Quiet
	$Reboottime= Get-WmiObject win32_operatingsystem -ComputerName $servername| select @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
	if($pingstatus -eq 'true')
    {$ping='Online'}
    Else
    {$ping='Offline'}
	
    $Result += New-Object PSObject -Property @{
    
        ServerName  =    $ServerName
		Status      =    $Ping
		RebootTime  =    $Reboottime.LastBootUpTime
	}
}

if($Result -ne $null)
{
	$HTML = '<style type="text/css">
	#Header{font-family:"Trebuchet MS", Arial, Helvetica, sans-serif;width:100%;border-collapse:collapse;}
	#Header td, #Header th {font-size:14px;border:1px solid #98bf21;padding:3px 7px 2px 7px;}
	#Header th {font-size:14px;text-align:left;padding-top:5px;padding-bottom:4px;background-color:#A7C942;color:#fff;}
	#Header tr.alt td {color:#000;background-color:#EAF2D3;}
	</Style>'

    $HTML += "<HTML><BODY><Table border=1 cellpadding=0 cellspacing=0 id=Header>
		<TR>
			<TH><B>Server Name</B></TH>
			<TH><B>Result</B></TH>
            <TH><B>RebootTime</B></TH>
			
		</TR>"
         Foreach($Entry in $Result)
         {
        if($Entry.Status -ne "Online")
		{
			$HTML += "<TR bgColor=Red>"
		}
		else
		{
			$HTML += "<TR>"
		}
		$HTML += "
	<TD>$($Entry.ServerName)</TD>
	<TD>$($Entry.Status)</TD>
    <Td>$($Entry.RebootTime)</TD>
						
	</TR>"
    }
    $HTML += "</Table></BODY></HTML>"

	$HTML | Out-File $OutputFile 
}


###### service check #######

$Style = @"
<style>
BODY{font-family:Calibri;font-size:12pt;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse; padding-right:5px}
TH{border-width: 1px;padding: 5px;border-style: solid;border-color: black;color:black;background-color:#FFFFFF }
TH{border-width: 1px;padding: 5px;border-style: solid;border-color: black;background-color:Red}
TD{border-width: 1px;padding: 5px;border-style: solid;border-color: black}
</style>
"@

$xrs=Gc $rebooted
foreach($xr in $xrs)
{
$ser=get-WmiObject  -Class Win32_Service -ComputerName $xr  | Where-Object {$_.State -ne "Running" -and $_.StartMode -eq "Auto"} |`
 Select-Object @{n="Computername";e={$xr}},DisplayName,State,StartMode 
 }
 if($ser){
 $ser| ConvertTo-Html -body "<H2>Services Not Started</H2>" -Head $Style |Out-File $servicefail
 }


 #### send email #############
 
if(test-path -Path $servicefail)
{ 
$body = [System.IO.File]::ReadAllText($OutputFile)
$MailMessage = @{ 
    To = $emailto 
    From = $emailFrom 
    Subject = "Server Reboot status and Service Fails" 
    Body = "Status of restart, Attached contains list of services not started" + $body
    Smtpserver = $smtpserver 
    attachment=$servicefail
}
Send-MailMessage @MailMessage -BodyAsHtml
 }

else {
$MailMessage = @{ 
    To = $emailto 
    From = $emailFrom 
    Subject = "Server Reboot And Uptime Status" 
    Body = "Status of restart" + $body
    Smtpserver = $smtpserver 
}
Send-MailMessage @MailMessage -BodyAsHtml
 }


# delete not necssary files

Remove-Item -Path $rebooted -Force
Remove-Item -Path $servicefail -Force
Remove-Item -Path $OutputFile -force