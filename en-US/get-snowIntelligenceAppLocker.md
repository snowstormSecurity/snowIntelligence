﻿# get-snowIntelligenceAppLocker

## SYNOPSIS
Collects the AppLocker status from systems within the environment

## SYNTAX

### Set 1
```
get-snowIntelligenceAppLocker [[-configurationFile] <String>] [<CommonParameters>]
```

## DESCRIPTION
Queries the `Assets` table within snowIntelligence for a list of systems to check, then performs a remote connection to collect the results.

## EXAMPLES
```powershell
C:\PS> get-snowIntelligenceAppLocker | import-snowIntelligenceResults
```
## PARAMETERS

### configurationFile
```yaml
Type: String
Aliases: 

Required: false
Position: 9
Default Value: $snowIntelligenceConfigPath
Pipeline Input: false
```

### \<CommonParameters\>
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None


## OUTPUTS

### System.Object


## NOTES

## RELATED LINKS


*Generated by: PowerShell HelpWriter 2020 v2.3.47*
