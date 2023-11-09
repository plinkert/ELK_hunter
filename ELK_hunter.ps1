#If not exist, install PersistenceSniper
If(-not(Get-InstalledModule PersistenceSniper -ErrorAction SilentlyContinue)){
    Install-Module PersistenceSniper -Confirm:$False -Force
}
Import-Module PersistenceSniper

#SSL Certyficate bypass - this part only in case is ELK have only self sign certyficate
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Variables
$ApiKey = "<ELK_APIKEY>"
$elk = "<ELK_IP>"
$indexName = "<INDEX_NAME>"
$port = "<ELK_PORT>"

$uriELK = "https://${elk}:${port}/${indexName}"
$apiAuthHeader = "ApiKey $ApiKey"
$timeStamp = (Get-Date -Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss")
$hostname = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
$headers=@{
    Authorization=$apiAuthHeader
    "Content-Type"="application/x-ndjson"
}
$newData = Find-AllPersistence

#######################################
#Function
#######################################

function pushData($pushObject)
{
    Add-Member -InputObject $pushObject -MemberType NoteProperty -Name "TimeStamp" -Value $timeStamp
    $body=@"
    $($pushObject | ConvertTo-Json)
"@
    $response = Invoke-RestMethod -Uri "$uriELK/_doc" -Method Post -Headers $headers -Body $body
}

#####################################
#Script
#####################################

$elkData = Invoke-RestMethod -Uri "$uriELK/_search?q=Hostname:${hostname}&size=100" -Method GET -Headers $headers 
$elkData.hits

if ($elkData.took -eq 0)
{
    foreach ($i in $newData)
    {
        pushData($i)
    }
}
Else
{
    foreach ($persistenceObject in $newData)
    {
        $verification = $false
        foreach ($elkObject in $elkData.hits.hits._source)
        {
            if ($persistenceObject.Value -eq $elkObject.Value -AND $persistenceObject.Path -eq $elkObject.Path )
            {
                $verification = $true
            }
        }
        if (-Not $verification)
        {
            pushData($persistenceObject)
        }
    }
}
