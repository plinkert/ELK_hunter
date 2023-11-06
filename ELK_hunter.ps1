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
$headers=@{
    Authorization=$apiAuthHeader
    "Content-Type"="application/x-ndjson"
}
$timeStamp = (Get-Date -Date $(Get-Date).ToUniversalTime() -Format "yyyy-MM-ddTHH:mm:ss")

$persistence = Find-AllPersistence

foreach ($i in $persistence)
{
    Add-Member -InputObject $i -MemberType NoteProperty -Name "TimeStamp" -Value $timeStamp
    $body=@"
    $($i | ConvertTo-Json)
"@
    $response = Invoke-RestMethod -Uri "$uriELK/_doc" -Method Post -Headers $headers -Body $body
}
