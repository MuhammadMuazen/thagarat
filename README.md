# THAGART

Thagart was made to help me and others to get the latest information for the CVEs using the Shodan CVE DB API.

---
## Usage:

```

       ______________________________________________________________
      |~|~|~|~|~|~|~|~|~|~|~|~|~|THAGARAT|~|~|~|~|~|~|~|~|~|~|~|~|~|~|
       ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
     _________________________________________________________________
    |OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO|
    |_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
    |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
    |  Automate The Shodan CVE API To Get The Latest CVEs Information |
    |\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\|
    |_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
    |OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO|
     ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
      _______________________________________________________________
     |->|->| BY: Muhammad Muazen --> github.com/MuhammadMuazen |<-|<-|
      ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
[i] Usage:

        thagarat.exe [mandatory parameters] [options]

[i] Mandatory Parameters:

        --cve-id, -cid <CVE-ID>  [options]  Retrieve information for specific CVE ID.
        --cves, -cs              [options]  Retrieve information for all available CVEs.
        --help, -h                          Print the simple help message
        --full-help, -fh                    Print the full help message

[i] Options:

        [+] Options for both { --cve-id, -cid } and { --cves, -cs }:

            -id                             Return the id of the CVE
            -kev                            Return the KVE for the CVE
            -cpes                           Return the CPES for the CVE
            -epss                           Return the EPSS of the CVE
            -cvss                           Return the CVSS for the CVE
            -cvss-v3                        Return the CVSS-V3 version for the CVE
            -cvss-v2                        Return the CVSS-V2 version for the CVE
            -summary                        Return the summary that describes the CVE
            -references                     Return the references for the CVE
            -ranking-epss                   Return the ranking EPSS for the CVE
            -cvss-version                   Return the CVSS version for the CVE
            -published-time                 Return the publish time for the CVE
            -propose-action                 Return the propose action for the CVE
            -ransomware-campaign            Return the ransomware campaign for the CVE

        [+] Options specifed for { --cves, -cs }:

            -is-kev                         Returns only CVEs with the kev flag set to true.
            -sort-by-epss                   Sorts CVEs by the EPSS score in descending order
            -skip <number>                  Number of CVEs to skip in the result set
            -limit <number>                 The maximum number of CVEs to return in a single query
            -end-date   <date>              End date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -start-date <date>              Start date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -product <product_name>         Return the CVEs that have the product name
          
[i] Examples:

        [1] thagarat.exe -cs
        [2] thagarat.exe -cid CVE-CVE-2023-50071
        [3] thagarat.exe --cve-id CVE-2024-6387 -id -kev -references
        [4] thagarat.exe --cves -id -limit 10 -start-date 2023-10-01T12:01:44 -cpes -published-time 
```
---
## Build:
	 git clone https://github.com/MuhammadMuazen/thagarat
	 cd thagarat/
	 cargo build --release   
---
## About the Installer:
I am using inno setup compiler to for setting up the program you can find the installing script in the assets directory in the project
  
