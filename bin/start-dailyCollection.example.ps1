new-snowIntelligenceFolderStructure

### SYSTEM COLLECTION ###
get-snowIntelligenceAssetInventory | import-snowIntelligenceResults
get-snowIntelligenceVulnerabilityInventory | import-snowIntelligenceResults

get-snowIntelligencePolicyComplianceInventory -populationName 'policyServerOSs' | import-snowIntelligenceResults

get-snowIntelligenceLocalGroupMemberInventory -verbose | import-snowIntelligenceResults
get-snowIntelligenceAppLocker  -verbose | import-snowIntelligenceResults

### ACCOUNT COLLECTION ###
get-snowIntelligenceADAccountInventory | import-snowIntelligenceResults
get-snowIntelligenceADGroupMembership | import-snowIntelligenceResults

### PEOPLE COLLECTION ###
get-snowIntelligencePeopleInventory | import-snowIntelligenceResults

convert-CSVtosnowIntelligenceXML -path <secAwarenessPath> | import-snowIntelligenceResults
convert-CSVtosnowIntelligenceXML -path <PhishingPath> | import-snowIntelligenceResults

