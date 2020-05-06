new-secInsightFolderStructure

### SYSTEM COLLECTION ###
get-secInsightAssetInventory | import-SecInsightResults
get-secInsightVulnerabilityInventory | import-SecInsightResults

get-secInsightPolicyComplianceInventory -populationName 'policyServerOSs' | import-SecInsightResults

get-secInsightLocalGroupMemberInventory -verbose | import-SecInsightResults
get-SecInsightAppLocker  -verbose | import-SecInsightResults

### ACCOUNT COLLECTION ###
get-secInsightADAccountInventory | import-SecInsightResults
get-secInsightADGroupMembership | import-SecInsightResults

### PEOPLE COLLECTION ###
get-secInsightPeopleInventory | import-SecInsightResults

convert-CSVtoSecInsightXML -path <secAwarenessPath> | import-secInsightResults
convert-CSVtoSecInsightXML -path <PhishingPath> | import-secInsightResults

