# chkp-disabledrules.ps1
Powershell script to list all disabled rules from a Checkpoint policy.

The script uses Checkpoint webservices api to connect to a management server and list all disabled rules from a specified access layer. The results can be exported as as .html file or displayed as host output. 

The script as been tested on R81.10 with api version 1.8.1 and above, but it should also works with older versions. No compatibility with MDS yet. 

## Parameters

- **[-server]**, Checkpoint management server's ip address or fqdn.
- **[-user]**, user with sufficient permissions on the management server.
- **[-password]**, password for the api user.
- **[-accesslayer]**, access layer's name that corresponds to the policy package you want to list disabled rules from.
- **[-outputfile]**, filepath where you want to export the results. This should be a .html file.

## Examples

```
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard"
```

Runs the script then asks the user for password then returns all rules that are currently disabled in the access layer named "Standard".

```
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard"
```

Runs the script then asks the user for password then returns all rules that are currently disabled in the access layer named "Standard".

```
"./chkp-disabledrules.ps1" -Server 192.168.1.50 -user admin -Policy "Standard" -Outputfile "C:\Temp\rules.html"
```

Runs the script and export the results to C:\Temp\rules.html.
