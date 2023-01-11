<#

.SYNOPSIS
This script is intended to list all disabled rules from a Checkpoint policy.

.DESCRIPTION
The script uses Checkpoint webservices api to connect to a management server and list all disabled rules from a specified access layer. The results can be exported as as .html file. 

.EXAMPLE
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard"
Runs the script then asks the user for password then returns all rules that are currently disabled in the access layer named "Standard".

.EXAMPLE
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard"
Runs the script then asks the user for password then returns all rules that are currently disabled in the access layer named "Standard".

.EXAMPLE
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard" -Outputfile "C:\Temp\rules.csv"
Runs the script and export the results to C:\Temp\rules.csv.

.INPUTS
Server : ip address of the Checkpoint management server
User : user with sufficient permissions on the checkpoint management server
Password : password for the api user 
AcessLayer : Access layer's name you want to list disabled rules from
Outputfile : Filepath to export the results to a html file

.NOTES
Written by : Lucas Bablon
Version : 1.0
    
#>

#params
param 
(
    [Parameter(Mandatory=$true, HelpMessage="Checkpoint Management api's ip")]
    [string]$server,
    [Parameter(Mandatory=$true, HelpMessage="User with api management permission")]
    [string]$user,
    [Parameter(Mandatory=$false, HelpMessage="Password")]
    [string]$password,
    [Parameter(Mandatory=$true, HelpMessage="Access layer's name")]
    [string]$accesslayer,
    [Parameter(Mandatory=$false, HelpMessage="Export path for the html file")]
    [string]$outputfile
)

#tls support
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

##
##VARIABLES
##

#html and css styling for outputfile
$html="<style>"
$html=$html+"BODY{background-color:white;font-family: Arial;}"
$html=$html+"TABLE{border: 1px;border-collapse: collapse;}"
$html=$html+"TH{border: 1px solid #ddd;padding: 15px;background-color: #300e7b;font-family: Arial;color: white;text-align: left;}"
$html=$html+"TD{border: 1px solid #ddd;padding: 15px;background-color: white;font-family: Arial;}"
$html=$html+"</style>"

$htmlintro=@"
    <br>
    <i>This report has been generated on $date for access layer "$accesslayer" on Checkpoint management server $server.</i>
    <br>
    <br>
"@

#reset variables from previous run
$response=""
$sid=""
$rules=""

##
## FUNCTIONS
##

function chkp-login 
{
    param 
    (
        [Parameter(Mandatory=$true, HelpMessage="Checkpoint Management api's ip")]
        [string]$server,
        [Parameter(Mandatory=$true, HelpMessage="User with api management permission")]
        [string]$username,
        [Parameter(Mandatory=$true, HelpMessage="Password")]
        [string]$password
    )

    #body
    $body=@{

        "user"="$username"
        "password"="$password"
        "enter-last-published-session"="true"

    }
    
    $body=$body| convertto-json -compress
    
    #create login URI
    $loginURI="https://${server}/web_api/login"

    #allow self-signed certificates
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}

    #api call
    $response=Invoke-WebRequest -Uri $loginURI -Body $body -ContentType application/json -Method POST

    #make the content of the response a powershell object
    $responsecontent=$response.Content | ConvertFrom-Json

    #return sid
    $sid=$responsecontent.sid
    return $sid
}

function chkp-logout 
{
    param 
    (
        [Parameter(Mandatory=$true, HelpMessage="Checkpoint Management api's ip")]
        [string]$server,
        [Parameter(Mandatory=$true, HelpMessage="api session id")]
        [string]$sid
    )

    #body
    $body=@{}
    $body=$body| convertto-json -compress
    
    #headers
    $headers=@{"x-chkp-sid"=$sid}
    $global:headers=$headers | ConvertTo-Json -Compress

    #create logout URI
    $logoutURI="https://${server}/web_api/logout"

    #api call
    $response=Invoke-WebRequest -Uri $logoutURI -Body $body -Headers $headers -ContentType application/json -Method POST
}

##
## SCRIPT
## 

#password prompt
if (! $password) 
{
    $creds=get-credential -message "Please enter password" -username $user
    $password=$creds.GetNetworkCredential().password
}

#login
Write-Host "`n"
Write-Host "Connecting to api..."

try
{
    $sid=chkp-login -server $server -username $user -password  $password
}
catch
{
    #exit because could not establish a session with api
    Write-Host "Could not establish session with management server $server"
    Write-Warning $_.exception.message
    exit
}

Write-Host "Session established.`n"

#initiliaze array that will contains all rules
$allrules=@()

#offset corresponds to the rule number from where the api will start to query
$offset=0

#headers
$headers=@{"x-chkp-sid"=$sid}

$global:headers=$headers | ConvertTo-Json -Compress

#api request to get the total number of rules so that we can use the progress bar
$body=@{

    "details-level"="standard"
    "name"=$AccessLayer
    "use-object-dictionary"="false"
    "show-hits"="true"
    "offset"=0
    "limit"=1

}

$body=$body | ConvertTo-Json -Compress

#request
$requestURI="https://${server}/web_api/show-access-rulebase"
$response=Invoke-WebRequest -Uri $requestURI -Body $body -ContentType application/json -Method POST -Headers $headers

#make the content of the response a powershell object and get total number of rules
$rulesnumber=$response | ConvertFrom-Json
$rulesnumber=$rulesnumber.total

#query all rules from offset to total number of rules with a limit of 50 because more than that in a single request seems to be stressful for the management server
Write-Host "Fetching access rules from access layer $accesslayer..."

#save fecthing execution time to display later
$exectime=[System.Diagnostics.Stopwatch]::StartNew()

do 
{
    #progress bar
    $completed=[math]::round(($offset/$rulesnumber)*100)
    Write-Progress -Activity "Listing all rules" -Status "$completed% complete" -PercentComplete $completed
    Start-Sleep -Milliseconds 300

    #body
    #in a general way the api is limited to 500 objects for each request. 100 and above are too slow, 50 is more precise to display task advancement 
    #do not set the details-level to full unless you really need it because it will slow down the query and cause errors 500 and 400
    $body=@{

        "details-level"="standard"
        "name"=$AccessLayer
        "use-object-dictionary"="false"
        "show-hits"="true"
        "offset"=$offset
        "limit"=100

    }

    $body=$body | ConvertTo-Json -Compress

    #request
    $requestURI="https://${server}/web_api/show-access-rulebase"
    $response=Invoke-WebRequest -Uri $requestURI -Body $body -ContentType application/json -Method POST -Headers $headers
   
    #make the content of the response a powershell object
    $rules=$response | ConvertFrom-Json

    #merge previous result from the do loop with current request
    $allrules+=$rules.rulebase.rulebase

    #set offset to the last rule listed by the query
    $offset=$rules.to

#if the last rule from current query is not equal to the total rules number we loop again
} while ($offset -ne $rulesnumber)

$exectime.stop()

#display fetch exec time
Write-Host "Done. $rulesnumber rules were fetched in "$exectime.elapsed.totalseconds" seconds.`n"

#here you can customize the output with the information you need
$allrules=$allrules | % {

    $i=$_
    New-Object -TypeName psobject -Property @{

        'rule-number'=$i.'rule-number'
        'name'=$i.name
        'source'=$i.source.name -join ";"
        'source-negate'=$i.'source-negate'
        'destination'=$i.destination.name -join ";"
        'destination-negate'=$i.'destination-negate'
        'services'=$i.service.name -join ";"
        'action'=$i.action.name
        'track'=$i.track.type.name
        'comments'=$i.comments
        'install-on'=$i.'install-on'.name
        'enabled'=$i.enabled
        'hits'=$i.hits.value
        'creation-time'=$i.'meta-info'.'creation-time'.'iso-8601'
        'owner'=$i.'meta-info'.creator
        'last-modify-time'=$i.'meta-info'.'last-modify-time'.'iso-8601'
        'last-modifier'=$i.'meta-info'.'last-modifier'
        'uid'=$i.uid

    }
}
##
##PROCESS RESULTS
##

#select rules with 0 hits
$disabledrules=$allrules | ? {$_.enabled -like "False"}
$rulescount=$disabledrules.count

Write-Output "The following $rulescount rules are currently disabled :`n" 
$disabledrules | select 'rule-number','name','enabled','uid' | ft

##
## EXPORT
##

#if output file was specified then export the results in html
if ($outputfile) 
{
    $htmltitle=@"
    <br>
    <font size="+3"><b>Disabled rules from $accesslayer</b></font>
    <br>
    <br>
    
"@

    $htmlintro | Out-File $outputfile -Append
    $htmltitle  | Out-File $outputfile -Append
    
    $disabledrules |
        Sort 'rule-number' | 
        Select 'policy','rule-number','name','source','source-negate','destination','destination-negate','services','action','track','comments','install-on','enabled','hits','creation-time','owner','last-modify-time','last-modifier','uid' |
        ConvertTo-Html -Head $html |
        Out-File $outputfile -Append

    $filepath=(Get-ChildItem $outputfile).versioninfo.filename
    Write-Output "Report has been saved in $filepath.`n"
}

##
##LOGOUT
##

#terminates api current session
Write-Host "Closing connection with management server..."
chkp-logout -server $server -sid $sid
Write-Host "Done.`n"
