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


#Body require to mapping
$body=@"
{
    "mappings":{
        "properties":{
            "TimeStamp":{"type":"date"},
            "Hostname":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Technique":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Classification":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Path":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Value":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Access Gained":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Note":{"type":"text"},
            "Reference":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "Signature":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "IsBuiltinBinary":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "IsLolbin":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            },
            "VTEntries":{
                "type":"text",
                "analyzer":"english",
                "fields":{
                    "raw":{
                        "type":"keyword"
                    }
                }
            }
        }
    }

}
"@

##Create an index mapping
$response = Invoke-RestMethod -Uri "$uriELK" -Method Put -Headers $headers -Body $body
$response | ConvertTo-Json

##Fetch a mapping 
$response = Invoke-RestMethod -Uri "$uriELK/_mapping" -Method Get -Headers $headers 
$response | ConvertTo-Json
