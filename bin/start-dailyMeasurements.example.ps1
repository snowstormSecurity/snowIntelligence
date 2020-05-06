##### SYSTEM MEASUREMENTS #####
# Vulnerability Measurements
Write-Verbose "START: Vulnerability Measurements" -Verbose
Write-Verbose " - vulnScore_avgCVSS" -verbose
measure-secInsightConfiguration -populationName 'vulnScore_avgCVSS' -measurementVersion 3 | import-secInsightResults
Write-Verbose " - vulnScore_maxCVSS" -verbose
measure-secInsightConfiguration -populationName 'vulnScore_maxCVSS' -measurementVersion 3 | import-secInsightResults -noClearCurrentTable
Write-Verbose "END  : Vulnerability Measurements" -Verbose

# Policy Compliance Measurement
Write-Verbose "START: Policy Compliance Measurements" -Verbose
measure-secInsightConfiguration -populationName 'policyCompliance_Score' -measurementVersion 1 | import-secInsightResults -noClearCurrentTable
Write-Verbose "END  : Policy Compliance Measurements" -Verbose

# Local Administrator Count Measurement
Write-Verbose "START: System Measurements" -Verbose
Write-Verbose " - localAdministrator_score" -verbose
measure-secInsightConfiguration -populationName 'localAdministrator_Score' -measurementVersion 1 | import-secInsightResults -noClearCurrentTable
Write-Verbose " - appLocker_exe" -verbose
measure-secInsightConfiguration -populationName 'appLocker_exe' -measurementVersion 1 | import-secInsightResults -noClearCurrentTable
Write-Verbose "END  : System Measurements" -Verbose

#### PEOPLE MEASUREMENTS ####
Write-Verbose "START: People Measurements" -Verbose
Write-Verbose " - phishing_Score" -verbose
measure-secInsightConfiguration -populationName 'phishing_Score' -measurementVersion 1 | import-secInsightResults
Write-Verbose " - securityAwareness_Score" -verbose
measure-secInsightConfiguration -populationName 'securityAwareness_Score' -measurementVersion 1 | import-secInsightResults -noClearCurrentTable
Write-Verbose "END  : People Measurements" -Verbose
