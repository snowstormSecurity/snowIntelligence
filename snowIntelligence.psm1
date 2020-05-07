###  SUPPORT COMPONENTS ###
function new-snowIntelligenceTable {
    <#
        .EXTERNALHELP snowIntelligence.psm1-Help.xml
    #>
        [CmdletBinding()]
        param (
            [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][string]$json,
            [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)][switch]$noHistoryTable
        )
        
        #region Load Configuration File
        Write-Verbose "BEGIN: Load Configuration File"
        if ((test-path $json) -eq $false) { Write-Error "Unable to load configuration file $json"; break }
        $config = Get-Content $json -raw | Convertfrom-Json
        #endregion
        
        Write-Verbose "Get Table Definitions"
        forEach ($table in ($config.tables | get-member | where-object{ $_.memberType -eq 'NoteProperty' }).name) {
            Write-Verbose "START: $table"

            Write-Verbose " - Test for Table existance"
            $tableExists = $null
            $sqltest = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE [Table_Name] = '$table'"
            $tableExists = invoke-sqlFunction -server $config.sqlInstance.Server -database $config.sqlInstance.database -sql $sqlTest

            if($null -eq $tableExists){
                Write-Verbose " - $($table) not found in $($config.sqlInstance.database) on $($config.sqlInstance.server)"
                Write-Verbose " - Creating Table $($table)"

                $tableDefinition = $config.tables.$table
                $sqlInsert = "CREATE TABLE [dbo].[$table] ("
                $sqlInsertHistory = "CREATE TABLE [dbo].[$($table)_History] ("
                $sqlColumns = ""
                Write-Verbose "   - Column Definitions:"
                ForEach ($column in ($tableDefinition.psobject.Properties | where-object{ $_.memberType -eq 'NoteProperty' })) {
                    Write-Verbose "      [$($column.Name)] $($column.Value),"
                    $sqlColumns += "[$($column.Name)] $($column.Value),"
                }
                
                $sqlColumns = $sqlColumns.trimend(',', 1) + ")"
                
                $sqlInsert += $sqlColumns
                $sqlInsertHistory += $sqlColumns
                
                # Execute SQL
                Write-Verbose " - Create $table on $($config.sqlInstance.Server) in $($config.sqlInstance.database)"
                invoke-sqlFunction -server $config.sqlInstance.Server -database $config.sqlInstance.database -sql $sqlInsert
                Write-Verbose "   - Results for $($table): $($?)" -verbose
                
                if ($noHistoryTable -eq $false) {
                    # Execute SQL History
                    Write-Verbose " - Create $($table)_history on $($config.sqlInstance.Server) in $($config.sqlInstance.database)"
                    invoke-sqlFunction -server $config.sqlInstance.Server -database $config.sqlInstance.database -sql $sqlInsertHistory
                    Write-Verbose "   - Results for $($table)_History: $($?)" -verbose
                }
            }
            else
            {
                Write-Verbose " - Table Found"

            }
            Write-Verbose "END: $table"
        }
}
function repair-sqlText($text) {
	if ($null -eq $text) { return $null }
	else {
		$newText = $text.replace("'", "''").replace('"', '""')
		return $newText
	}
}
function invoke-sqlFunction {	
	##############################################################################
    ##
    ## Invoke-SqlCommand.ps1
    ##
    ## From Windows PowerShell Cookbook (O'Reilly)
    ## by Lee Holmes (http://www.leeholmes.com/guide)
    ##
    ## Return the results of a SQL query or operation
    ##
    ## ie:
    ##
    ##    ## Use Windows authentication
    ##    Invoke-SqlCommand.ps1 -Sql "SELECT TOP 10 * FROM Orders"
    ##
    ##    ## Use SQL Authentication
    ##    $cred = Get-Credential
    ##    Invoke-SqlCommand.ps1 -Sql "SELECT TOP 10 * FROM Orders" -Cred $cred
    ##
    ##    ## Perform an update
    ##    $server = "MYSERVER"
    ##    $database = "Master"
    ##    $sql = "UPDATE Orders SET EmployeeID = 6 WHERE OrderID = 10248"
    ##    Invoke-SqlCommand $server $database $sql
    ##
    ##    $sql = "EXEC SalesByCategory 'Beverages'"
    ##    Invoke-SqlCommand -Sql $sql
    ##
    ##    ## Access an access database
    ##    Invoke-SqlCommand (Resolve-Path access_test.mdb) -Sql "SELECT * FROM Users"
    ##    
    ##    ## Access an excel file
    ##    Invoke-SqlCommand (Resolve-Path xls_test.xls) -Sql 'SELECT * FROM [Sheet1$]'
    ##############################################################################
    ##  Jason Bohreer
    ##      2016-05-02 Extended function to include the capability to handle Oracle databases
    ##
    ##############################################################################
    
    param(
        [parameter(Position=0 ,Mandatory=$false,ValueFromPipeLine=$false)] [string] $server,
        [parameter(Position=1 ,Mandatory=$false,ValueFromPipeLine=$false)] [string] $database,
        [parameter(Position=2 ,Mandatory=$true,ValueFromPipeLine=$false)] [string] $sql,
        [parameter(Position=3 ,Mandatory=$false,ValueFromPipeLine=$false)] [string] $sid,
        [parameter(Position=4 ,Mandatory=$false,ValueFromPipeLine=$false)] [string] $oracleUser,
        [parameter(Position=5 ,Mandatory=$false,ValueFromPipeLine=$false)] [string] $oraclePassword,
        [parameter(Position=6 ,Mandatory=$false,ValueFromPipeLine=$false)] [int] $connectTimeout=120,
        [parameter(Position=9 ,Mandatory=$false,ValueFromPipeLine=$false)] [System.Management.Automation.PsCredential] $credential
      )
    
    
    If($sid -ne ""){
        $connectionString = "Provider=OraOLEDB.Oracle;User ID=$oracleUser;Password=$oraclePassword;Data Source=$sid;"
    }
    elseif($server -ne ""){
        $authentication = "Integrated Security=SSPI;"
        
        ## If the user supplies a credential, then they want SQL
        ## authentication
        if($credential){
            $plainCred = $credential.GetNetworkCredential()
            $authentication =
                ("uid={0};pwd={1};" -f $plainCred.Username,$plainCred.Password)
        }
        
        ## Prepare the connection string out of the information they
        ## provide
        $connectionString = "Provider=sqloledb;Data Source=$server;Initial Catalog=$database;Connect Timeout=$connectTimeout;$authentication; "    
    }
    else{
        $connectionString = "Provider=sqloledb;Data Source=$server;Initial Catalog=$database;Connect Timeout=$connectTimeout;$authentication; "    
    }
    
    ## Connect to the data source and open it
    $connection = New-Object System.Data.OleDb.OleDbConnection $connectionString
    $command = New-Object System.Data.OleDb.OleDbCommand $sql,$connection
    $connection.Open()
    
    ## Fetch the results, and close the connection
	$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command
	
	# Fixed SQL Timeout issue (https://stackoverflow.com/questions/47073578/powershell-sql-server-database-connectivity-and-connection-timeout-issue)
	$adapter.SelectCommand.CommandTimeout=$connectTimeout

	$dataset = New-Object System.Data.DataSet
	
    [void] $adapter.Fill($dataSet)
    $connection.Close()
    
    ## Return all of the rows from their query
    [Array] $output =  $dataSet.Tables | Select-Object -Expand Rows
    Write-Output $output
}
function import-snowIntelligenceResults {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)][object]$resultObject,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)][string]$resultsFile,
        [parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 8)][switch]$noClearCurrentTable,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	#endregion
	
	#region Load Results File
	if ($resultObject) { $resultsFile = $resultObject.OutputFullName }
	
	Write-Verbose "BEGIN: Load Results File"
	if ((test-path $resultsFile) -eq $false) { Write-Error "Unable to load Results file $resultsFile"; break }
	$resultsFullName = (Get-Item $resultsFile).fullname
	$scriptType = $resultsFullName.Split('\')[-3]
	$name = $resultsFullName.split('\')[-2]
	$importXML = Import-Clixml $resultsFile
	
	# Get the Processed/Error Folders
	$processFolderPath = Join-path -path (Get-Item $resultsFullName).directoryName -ChildPath $snowIntelligenceConfiguration.paths.ProcessedFolder
	$errorFolderPath = Join-path -path (Get-Item $resultsFullName).directoryName -ChildPath $snowIntelligenceConfiguration.Paths.ErrorFolder
	#endregion
	
	#region Set Database Connection Information
	$sqlServer = $snowIntelligenceConfiguration.$scriptType.$name.sqlServer
	$database = $snowIntelligenceConfiguration.$scriptType.$name.Database
	$table = $snowIntelligenceConfiguration.$scriptType.$name.Table
	#endRegion
	
	#region Create Common SQL components	
	$sqlHeaderCurrent = "INSERT INTO $table "
	$sqlHeaderHistory = "INSERT INTO $table" + '_History '
	$sqlCurrentDelete = "DELETE FROM $table"
	$dateAdded = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    #endRegion
    
    # For query performance reasons, clear the 'Current' table by default.
    # Historical information will be appended within _History version of the table.
    if($noClearCurrentTable -eq $false){
    	invoke-sqlFunction -server $sqlServer -database $database -sql $sqlCurrentDelete
    }

	forEach ($item in $importXML) {
        if($null -ne $item){
            $fieldValues = ''
            $fields = $item | get-member | where-object{ $_.MemberType -match 'Property' }
            #Region Build Field List
            $sqlFieldList = ''
            ForEach ($fieldName in $fields.name) { $sqlFieldList += "[$fieldName]," }
            $sqlFieldList = "[DateAdded]," + $sqlFieldList.Substring(0, $sqlFieldList.length - 1)
            #EndRegion
            ForEach ($field in $fields) {
                
                # If Item type is not defined, set default as System.String
                if ($null -eq $item.($field.Name)) {
                    $fieldDataType = 'System.String'
                }
                else {
                    $fieldDataType = $item.($field.Name).psTypeNames[0]
                }
                
                # Define how SQL import will function, based on Data Type
                # Can be extended for other types, as needed.            
                if ($fieldDataType -eq 'System.DateTime') {
                    $fieldValues += "'$($item.($field.name))',"
                }
                elseif ($fieldDataType -eq 'Int') {
                    $fieldValues += "$($item.($field.name)),"
				}
				elseif ($fieldDataType -eq 'System.Decimal') {
                    $fieldValues += "$($item.($field.name)),"
                }
                elseif ($fieldDataType -eq 'System.String') {
                    $cleanValue = repair-sqlText -text ($item.($field.name))
                    $fieldValues += "'$cleanValue',"
                }
                else {
                    $fieldValues += "'$($item.($field.name))',"
                }
            }
            $fieldValues = "'$dateAdded'," + $fieldValues.Substring(0, $fieldValues.Length - 1)
            $sqlInsertCurrent = $sqlHeaderCurrent + '(' + $sqlFieldList + ') VALUES (' + $fieldValues + ')'
            $sqlInsertHistory = $sqlHeaderHistory + '(' + $sqlFieldList + ') VALUES (' + $fieldValues + ')'
            invoke-sqlFunction -server $sqlServer -database $database -sql $sqlInsertCurrent
            invoke-sqlFunction -server $sqlServer -database $database -sql $sqlInsertHistory
            Write-Verbose $sqlInsertCurrent
        }
	}
	
	# Move 
	$postInsert = "SELECT COUNT(DateAdded) AS Count FROM $($table) GROUP BY DateAdded HAVING (DateAdded = CONVERT(DATETIME, '$dateAdded', 102))"
	$postInsertCount = invoke-sqlFunction -server $sqlServer -database $database -sql $postInsert
	
	if ($postInsertCount.Count -eq $importXML.Count) {
		Write-Verbose "END: Successful Import"
		Move-Item -path $resultsFullName -Destination $processFolderPath
	}
	else {
		Write-Verbose "END: Error Detected"
		Move-Item -path $resultsFullName -Destination $errorFolderPath
	}
}
function set-snowIntelligenceConfiguration {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][string]$childPath = 'Config\snowIntelligence.json'
	)
	$global:snowIntelligenceConfigPath = Join-Path -path (get-module snowIntelligence).modulebase -ChildPath $childPath
	Write-Verbose ('Global Variable $snowIntelligenceConfigPath set to: ' + $snowIntelligenceConfigPath) -Verbose

	# Force System to check and build appropriate folder structure
	new-snowIntelligenceFolderStructure
}
function set-snowIntelligenceOutputInformation {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)][string]$scriptType,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)][string]$name,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	#region Load Configuration File
	Write-Verbose " * BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	#endregion
	
	#region Define Output Information
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd-hh-mm-ss')
	$resultsBase = Join-Path -path $snowIntelligenceConfiguration.paths.Output -ChildPath $snowIntelligenceConfiguration.paths.Results
	$resultsJobFolder = join-path (Join-path -path $resultsBase -ChildPath $scriptType) -ChildPath $name
	$errorFolder = Join-path $resultsJobFolder -ChildPath $snowIntelligenceConfiguration.Paths.errorFolder
	$ProcessedFolder = Join-path $resultsJobFolder -ChildPath $snowIntelligenceConfiguration.Paths.ProcessedFolder
	$RawFolder = Join-path $resultsJobFolder -ChildPath $snowIntelligenceConfiguration.Paths.RawFolder
	$outputFileName = $name + '.' + $dateAssessed + '.xml'
	$outputFullname = Join-path $resultsJobFolder -ChildPath $outputFileName
	#endRegion

	$diagOutputProperties = @{
        DateAssessed     = $dateAssessed
		ScriptType	     = $scriptType
		$name		     = $name
		ResultsBase	     = $resultsBase
		ResultsJobFolder = $resultsJobFolder
		ErrorFolder	     = $errorFolder
		ProcessedFolder  = $ProcessedFolder
		RawFolder	     = $RawFolder
		OutputFullName   = $outputFullname
	}
	$diagOutput = New-Object psObject -Property $diagOutputProperties
	$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.Outputs'
	Write-Output $diagOutput
}
function new-snowIntelligenceFolderStructure {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	#endregion
	
	# Get Tier1 Folders
	$tier1Folders = $snowIntelligenceConfiguration | get-member | where-object { $_.MemberType -eq 'NoteProperty' -and $_.name -ne 'paths' } | select-object Name
	
	# For Each Tier1 Folder
	ForEach ($tier1Folder in $tier1Folders) {
		if ($tier1Folder.name -ne 'email') {
			Write-Verbose "Start Check: $($tier1Folder.name)"
			$tier2Folders = $snowIntelligenceConfiguration.$($tier1Folder.name) | get-Member | where-object{ $_.MemberType -eq 'NoteProperty' } | Select-Object Name
			
			ForEach ($tier2Folder in $tier2Folders) {
				Write-Verbose "Start Check: \$($tier2Folder.name)"
				$tier3Folders = set-snowIntelligenceOutputInformation -scriptType ($tier1Folder.name) -name ($tier2Folder.name)
				$tier3FolderNames = $tier3Folders | Get-Member | where-object{ $_.Name -match 'Folder' } | Select-Object Name
				
				ForEach ($tier3FolderName in $tier3FolderNames) {
					Write-Verbose "   - Start Check: $($tier3FolderName.name)"
					# Test output folder
					if ((Test-Path ($tier3Folders.$($tier3FolderName.name))) -eq $false) {
						Write-Verbose " * Create Folder: $($tier3Folders.$($tier3FolderName.name))" -verbose
                        New-Item $tier3Folders.$($tier3FolderName.name) -ItemType Directory -Force | out-null
                        Write-Verbose " * Compress Folder: $($tier3Folders.$($tier3FolderName.name))" -verbose
						$trashResults= compact.exe /c ($tier3Folders.$($tier3FolderName.name))
					}
				}
			}
		}
	}
}
function convert-CSVtosnowIntelligenceXML{
	[CmdletBinding()]
	param (
        [parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)][string]$csvFile,
        [parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)][string]$populationName,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 2)][ValidateSet('Populations','Measurements')][string]$scriptType='Populations',
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	#region Load Required Modules
	    # No Additional Modules Required
	#endregion

	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if((test-path $configurationFile) -eq $false){Write-Error "Unable to load configuration file $configurationFile";break}
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$configuration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion

	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion

    # Get List of Table Columns
    $columns = invoke-sqlFunction -server $configuration.sqlServer -database $configuration.Database -sql "exec sp_columns $($configuration.Table)"
    $columns = $columns | where-object {$_.Column_Name -ne 'DateAdded' -and $_.Column_Name -ne 'DateAssessed' -and $_.Column_Name -ne 'Include'}

    # Open CSV File
    $csv = Import-CSV -path $csvFile

    # For Each Line
    $exportNewObject = ForEach($line in $csv){
        $diagOutputProperties = @{}
        ForEach($column in $columns.Column_Name){
            $diagOutputProperties.add($column,$line.$column)
        }
        $diagOutputProperties.add('DateAssessed',$dateAssessed)
        $diagOutputProperties.add('Include',1)

        $diagOutput = New-Object psObject -Property $diagOutputProperties
        $diagOutput.psobject.TypeNames[0] = "snowIntelligence.$populationName"
        $diagOutput
    }

    # Copy CSV --> Raw
    Copy-Item -path $csvFile -Destination (Join-path -path $outputObject.RawFolder -ChildPath ($populationName + '.' + $outputObject.DateAssessed + '.csv'))

    # If In RAW, then Remove
    If(Test-Path (Join-path -path $outputObject.RawFolder -ChildPath ($populationName + '.' + $outputObject.DateAssessed + '.csv'))){
        Remove-item $csvFile
    }

    $exportNewObject | Export-Clixml -path ($outputObject.OutputFullName)
    $outputObject
}

### SYSTEM FUNCTIONS ###
function get-snowIntelligenceAssetInventory {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'populations'
	$populationName = 'assets'
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$assetConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	
	#endRegion
	
	#region Collect Asset Information
    $sqlResults = invoke-sqlFunction -server ($assetConfiguration.assetServer) -database ($assetConfiguration.assetDatabase) -sql $assetConfiguration.assetView
    Write-Verbose "SQL: $($assetConfiguration.assetView)"

    # Collected Active Directory Computers
    $adComputers = get-adComputer -Filter * -Properties Description


	ForEach ($asset in $sqlResults) {
        Write-Verbose "Search for $($asset.Hostname) in AD"
        $Description = ''
        if($adComputers.name -contains $asset.hostname){
            $description = ($adComputers | where-object {$_.name -match $asset.hostname}).Description
        }
		add-member -InputObject $asset -MemberType 'NoteProperty' -Name 'Description' -Value $Description
		add-member -InputObject $asset -MemberType 'NoteProperty' -name 'DateAssessed' -Value $dateAssessed
		add-member -InputObject $asset -MemberType 'NoteProperty' -name 'Include' -Value 1
	}
	$sqlResults | Export-Clixml -path ($outputObject.OutputFullName)
	$outputObject
}
function get-snowIntelligenceVulnerabilityInventory {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'populations'
	$populationName = 'vulnerability'
	
	#region Load Required Modules
	if ($null -eq (Get-Module Qualys)) { Import-Module Qualys }
	#endregion
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$vulnConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion
	
	# Credentials
	$qualysCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $vulnConfiguration.username, ($vulnConfiguration.password | ConvertTo-SecureString)
    $unencryptedPassword = $qualysCredential.GetNetworkCredential().password
	
	# Force TLS1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	# Connect to Qualys API
	Write-Verbose 'Connect: Qualys' -verbose
	$global:qualysSessionAPI = Connect-qualysAPI -username $vulnConfiguration.username -password $unencryptedPassword -qualysurlBase $vulnConfiguration.URL
	
	# Collect Resources to Import
	#   NOTE: Qualys Arguments ARE CaSeSeNsItIvE
	Write-Verbose 'Qualys: GetVulnerabilityReport' -verbose
	$assetGroups = get-qualysAssetGroup | where-object{ $_.AssetGroup -match $vulnConfiguration.assetGroup }
	
	$hostVulnerability = ForEach ($assetGroup in $assetGroups) {
		
		# Qualys: Generate Report
		Write-Verbose "Qualys: Generate Report" -verbose
		$vulnerabilityReport = invoke-qualysReport -assetGroupIDs $assetGroup.ID -title ("snowIntelligence-vulnerabilityExport -" + $assetGroup.ID) -templateID $vulnConfiguration.templateID
		
		# Confirm Report has finished generating
		$pigsFly = $false
		$i = 0
		do {
			$report = get-QualysReport -id $vulnerabilityReport.ID
			if ($i -ge 30) { $pigsFly = $true }
			else { $i++ }
			if ($report.status -eq 'Finished') { $pigsFly = $true }
			else { Write-Verbose 'Waiting for pigs'; start-Sleep -second 60 }
		}
		until ($pigsFly)
		
		$rawFileName = $outputObject.OutputFullname.split('\')[-1].replace('.xml', '.raw.xml')
		$rawFullPath = Join-Path -Path $outputObject.RawFolder -childpath $rawFileName
        
        Write-verbose "Start XML Download"
		$reportFile = $report | new-qualysReportDownload -outputPath $outputObject.RawFolder
		if (Test-Path $rawFullPath) {
			remove-qualysReport -id $reportFile.ID
		}
        
        Write-verbose "Open XML Download"
		[XML]$xml = Get-Content $reportFile.FilePath
		
		ForEach ($Hostnode in $xml.ASSET_DATA_REPORT.Host_List.Host) {
			$ipAddress = $hostnode.IP
			$DNS = if ($null -eq $hostnode.dns) { '' }else { $hostnode.DNS."#cdata-section" }
			$osCPE = if ($null -eq $hostnode.OS_CPE."#cdata-section") { '' }else { $hostnode.OS_CPE."#cdata-section".Replace("/", "") }
			$NETBIOS = if ($null -eq $hostnode.NetBios."#cdata-section") { '' }else { $hostnode.NetBios."#cdata-section" }
			$operatingSystem = if ($null -eq $hostnode.Operating_System) { '' }else { $hostnode.Operating_System."#cdata-section"}
			
			
			$vulnDetails = foreach ($vulnDetail in $xml.ASSET_DATA_REPORT.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS) {
				$qid = $vulnDetail.QID."#text"
				$title = $vulnDetail.Title."#cdata-section"
				$severity = $vulnDetail.Severity
				$category = $vulnDetail.Category
				$cvssBase = if ($vulnDetail.CVSS_SCORE.cvss_base.GetType().name -eq 'XmlElement') { $vulnDetail.CVSS_SCORE.cvss_base."#text" }
				else { $vulnDetail.CVSS_SCORE.cvss_base }
				$cvssTemp = if ($vulnDetail.CVSS_SCORE.cvss_temporal.GetType().name -eq 'XmlElement') { $vulnDetail.CVSS_SCORE.cvss_Temporal."#text" }
				else { $vulnDetail.CVSS_SCORE.cvss_Temporal }
				
				$diagOutputProperties = @{
					Title    = $title
					QID	     = $qid
					Severity = $severity
					Category = $category
					cvssBase = $cvssBase
					cvssTemp = $cvssTemp
				}
				$diagOutput = New-Object psObject -Property $diagOutputProperties
				$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.Vulnerability.Detail'
				Write-Output $diagOutput
			}

            $vulnHosts = ForEach ($vulnerability in $hostnode.VULN_INFO_LIST.VULN_INFO) {
				$qid = $vulnerability.QID."#text"
				$firstFound = (Get-Date $vulnerability.FIRST_FOUND -Format 'yyyy-MM-dd HH:mm')
				$LastFound = (Get-Date $vulnerability.Last_FOUND -Format 'yyyy-MM-dd HH:mm')
				$timesFound = $vulnerability.Times_Found
				$vulnStatus = $vulnerability.VULN_Status
				$cvssFinal = if ($vulnerability.CVSS_FINAL -eq '-') { 0 }else { $vulnerability.CVSS_FINAL }
				$port = if ($null -eq $vulnerability.Port) { '0' }else { $vulnerability.Port[0] }
				$protocol = if ($null -eq $vulnerability.Protocol) { '' }else { $vulnerability.Protocol }
				
				$qidDetails = $vulnDetails | where-object{ $_.QID -eq $qid }
				
				$diagOutputProperties = @{
					DateAssessed    = $dateAssessed
					Include		    = 1
					ipAddress	    = $ipAddress
					DNS			    = $DNS
					osCPE		    = $osCPE
					NetBIOS		    = $NETBIOS
					OperatingSystem = $operatingSystem
					QID			    = $qid
					FirstFound	    = $firstFound
					LastFound	    = $LastFound
					TimesFound	    = $timesFound
					VulnStatus	    = $vulnStatus
					Protocol	    = $protocol
					Port		    = $port
					Category	    = $qidDetails.Category
					cvssFinal	    = $cvssFinal
					Title		    = $qidDetails.Title
					Severity	    = $qidDetails.Severity
					cvssBase	    = $qidDetails.cvssBase
					cvssTemp	    = $qidDetails.cvssTemp
					
				}
				$diagOutput = New-Object psObject -Property $diagOutputProperties
				$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.Vulnerability'
				Write-Output $diagOutput
			}
			
			$vulnHosts
		}
		Remove-Item $reportFile.FilePath
	}
	Write-Verbose "Write File to Output" -verbose
	$hostVulnerability | Export-Clixml -path ($outputObject.OutputFullName)
	$outputObject
	
	
	
}
function get-snowIntelligencePolicyComplianceInventory {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 9)][string]$populationName,	
	[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'populations'
	
	#region Load Required Modules
	if ($null -eq (Get-Module Qualys)) { Import-Module Qualys }
	#endregion
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$policyConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	if($null -eq $policyConfiguration){Write-Error "Unable to find $populationName";break}
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion
	
	# Credentials
	$qualysCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $policyConfiguration.username, ($policyConfiguration.password | ConvertTo-SecureString)
	$unencryptedPassword = $qualysCredential.GetNetworkCredential().password
	
	# Force TLS1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
	# Connect to Qualys API
	Write-Verbose 'Connect: Qualys' -verbose
	$global:qualysSessionAPI = Connect-qualysAPI -username $policyConfiguration.username -password $unencryptedPassword -qualysurlBase $policyConfiguration.URL
	
	# Collect Resources to Import
	#   NOTE: Qualys Arguments ARE CaSeSeNsItIvE
	Write-Verbose 'Qualys: GetPolicyReport' -verbose
	$assetGroups = get-qualysAssetGroup | Where-object{ $_.AssetGroup -match $policyConfiguration.assetGroup }
	
	$compliancePolicies = get-qualysCompliancePolicy -detail All
	[array]$compliancePolicies = $compliancePolicies | where-object{ $_.ID -eq $policyConfiguration.policyID }
	$exportSet = ForEach ($policy in $compliancePolicies) {
		Write-Verbose "Qualys Policy: $($policy.Title)" -verbose
        
        # Force reconnect to deal with Qualys timeout issues associated with large reports
		$global:qualysSessionAPI = Connect-qualysAPI -username $policyConfiguration.username -password $unencryptedPassword -qualysurlBase $policyConfiguration.URL
		
		# Insert Policy Controls (if appropriate)
		$sqlInsertStart = "INSERT INTO $($policyConfiguration.TableControls) ([ControlID],[Statement],[Criticality],[DateAdded])VALUES("
		
		Write-Verbose "Importing Controls (if needed)"
		ForEach ($control in $policy.Controls.control) {
			$controlID = $control.ID
			$statement = repair-sqlText $control.Statement."#cdata-section"
			$criticality = $control.Criticality.value
			#if ($statement.length -ge 255) { $statement = $statement.substring(0, 255) }
			$sqlInsertValues = $controlID + ",'" + $statement + "'," + $criticality + ",'" + $dateAssessed + "')"
			$sqlInsert = $sqlInsertStart + $sqlInsertValues
			if ((invoke-sqlFunction -sql "SELECT ControlID FROM $($policyConfiguration.TableControls) WHERE ControlID = $controlID" -server $policyConfiguration.sqlServer -database $policyConfiguration.Database).count -eq 0) {
				invoke-sqlFunction -sql $sqlInsert -server $policyConfiguration.sqlServer -database $policyConfiguration.Database
			}
		}
		
		Write-Verbose "Create Compliance Report"
		$complianceReport = invoke-qualysComplianceReport -assetGroupIDs $assetGroups.ID -title ("SMSexport - " + $policy.Title) -policy $policy.ID
		
		# Confirm Report has finished generating
		$pigsFly = $false
		$i = 0
		do {
			$report = get-QualysReport -id $complianceReport.ID
			if ($i -ge 30) { $pigsFly = $true }
			else { $i++ }
			if ($report.status -eq 'Finished') { $pigsFly = $true }
			else { Write-Verbose 'Waiting for pigs'; start-Sleep -second 60 }
		}
		until ($pigsFly)
		
		Write-Verbose "Download Compliance Report"
		# Download Report
		$reportFile = $report | new-qualysReportDownload -outputPath $outputObject.RawFolder
		
		Start-Sleep -Seconds 5
		if (Test-Path $reportFile.FilePath) {
			Write-Verbose "Remove Report" -Verbose
			$removeResults = remove-qualysReport -id $reportFile.ID
		}
		
		[XML]$xml = Get-Content $reportFile.FilePath
		
		$hosts = $xml.COMPLIANCE_POLICY_REPORT.RESULTS.HOST_LIST.HOST
        
        Write-Verbose "Process Download"
		ForEach ($hostnode in $hosts) {
			$DNS = ''
			$osCPE = ''
			
			$ipAddress = $hostnode.IP."#cdata-section"
			$trackingMethod = $hostnode.TRACKING_METHOD."#cdata-section"
			$DNS = $hostnode.DNS."#cdata-section"
			$osCPE = $hostnode.OS_CPE."#cdata-section".Replace("/", "")
			$NETBIOS = $hostnode.NetBios."#cdata-section"
			$operatingSystem = $hostnode.Operating_System."#cdata-section"
			
			$controls = $hostnode.Control_List.Control
			ForEach ($control in $controls) {
				$diagOutputProperties = @{
					DateAssessed = $dateAssessed
					Include	     = 1
					policyTitle  = $policy.Title
					ControlID    = $control.CID
					Status	     = $control.Status."#cdata-section"
					ipAddress    = $ipAddress
					trackingMethod = $trackingMethod
					DNS = $DNS
					osCPE = $osCPE
					NETBIOS	     = $NETBIOS
					operatingSystem = $operatingSystem
				}
				$diagOutput = New-Object psObject -Property $diagOutputProperties
				$diagOutput.psobject.TypeNames[0] = "snowIntelligence.Policy"
				Write-Output $diagOutput
			}
		}
	}
	$exportSet | Export-Clixml -path ($outputObject.OutputFullName) -Depth 1
	$outputObject
}
function Get-snowIntelligenceLocalGroupMemberInventory {
    <#
    #>
  
    [CmdletBinding()]
    param(
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
    )
	
	$scriptType = 'populations'
	$populationName = 'localGroupMembership'
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$localGroupConfig = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion

	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion

    # TODO: Get List of Active Windows Server (via config)
    Write-Verbose "Search for Systems: $($localGroupConfig.assetSQL)"
    $resultsAssets = invoke-sqlFunction -server $localGroupConfig.assetServer -database $localGroupConfig.assetDatabase -sql $localGroupConfig.assetSQL
    Write-Verbose " - Result Count: $($resultsAssets.count)"
    if($resultsAssets.count -ne 0){

        $exportSet = ForEach($computerName in $resultsAssets.Hostname){
            # TODO: For Each Computer in Computers, do the following

            Write-Verbose "BEGIN: $computerName"
            Write-verbose " - Get List of all Groups"
            $remoteGroups = get-wmiObject -Class Win32_Group -ComputerName $computerName -ErrorAction 'SilentlyContinue'
            if($null -eq $remoteGroups){
                Write-Verbose " - Unable to Connect to $computerName" -verbose
                $diagOutputProperties = @{
                    DateAssessed = $dateAssessed
                    Include	     = 1
                    Hostname  = $computerName
                    GroupName = 'NULL'
                    Member = 'NULL'
                    Type = 'NULL'
                }
                $diagOutput = New-Object psObject -Property $diagOutputProperties
                $diagOutput.psobject.TypeNames[0] = "snowIntelligence.LocalGroupMember"
                Write-Output $diagOutput
            }
            else{
                ForEach($remoteGroup in $remoteGroups.name){
                    Write-Verbose " - Get Group Members: $remoteGroup"
                    $adsiObject = ([adsi]"WinNT://$computerName/$remoteGroup,group").psbase.Invoke('Members')
                    ForEach($adsiItem in $adsiObject){
                  
                        $diagOutputProperties = @{
                            DateAssessed = $dateAssessed
                            Include	     = 1
                            Hostname  = $computerName
                            GroupName = $remoteGroup
                            Member = $adsiItem.GetType().InvokeMember('Name', 'GetProperty', $null, $adsiItem, $null)
                            Type = $adsiItem.GetType().InvokeMember('Class', 'GetProperty', $null, $adsiItem, $null)
                        }
                        $diagOutput = New-Object psObject -Property $diagOutputProperties
                        $diagOutput.psobject.TypeNames[0] = "snowIntelligence.LocalGroupMember"
                        Write-Output $diagOutput
                    }
                }
            }
        }
    }


    $exportSet | Export-Clixml -path ($outputObject.OutputFullName) -Depth 1
    $outputObject
    

}
function get-snowIntelligenceAppLocker {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'populations'
	$populationName = 'appLocker'
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$appLockerConfig = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion
	
	#region Collect Asset Information
    $sqlResults = invoke-sqlFunction -server ($appLockerConfig.assetServer) -database ($appLockerConfig.assetDatabase) -sql $appLockerConfig.assetView
    Write-Verbose "SQL: $($appLockerConfig.assetView)"

	$scriptBlock = {Import-Module AppLocker;[xml] $xml = Get-AppLockerPolicy -Effective -XML;$xml}
	$appLockerTypes = @('Appx','Dll','Exe','Msi','Script')
	$finalAppLocker = ForEach($asset in $sqlResults) {

        Write-Verbose "Connect to $($asset.Hostname) in AD"
		[xml] $appLockerResults = Invoke-Command -ComputerName $asset.hostname -ScriptBlock $scriptBlock

		if($null -eq $appLockerResults){
			ForEach($appLockerType in $appLockerTypes){
				$diagOutputProperties = @{
					DateAssessed = $dateAssessed
					Include = 1
					Hostname = $asset.Hostname
					Type = $appLockerType
					EnforcementMode = "Unknown" 
				}
				
				$diagOutput = New-Object psObject -Property $diagOutputProperties
				$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.AppLocker'
				Write-Output $diagOutput
			}
		}
		else{
			ForEach($appLockerResult in $appLockerResults.AppLockerPolicy.RuleCollection){
				$diagOutputProperties = @{
					DateAssessed = $dateAssessed
					Include = 1
					Hostname = $asset.Hostname
					Type = $appLockerResult.Type
					EnforcementMode = $appLockerResult.EnforcementMode 
				}
				
				$diagOutput = New-Object psObject -Property $diagOutputProperties
				$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.AppLocker'
				Write-Output $diagOutput
			}
		}
	}

	$finalAppLocker | Export-Clixml -path ($outputObject.OutputFullName)
	$outputObject
}

### USER FUNCTIONS ###
function get-snowIntelligenceADAccountInventory {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	$scriptType = 'populations'
	$populationName = 'adUserAccounts'
	
	#region Load Required Modules
	if (($null -eq (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory }
	#endregion

	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if((test-path $configurationFile) -eq $false){Write-Error "Unable to load configuration file $configurationFile";break}
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$userConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion

	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')

	#endRegion

	#region Collect Active Directory Information
	$adProperties = @('givenName','surname','samAccountName','emailaddress','sid','manager','title','company','enabled','passwordLastSet','whenCreated','whenChanged','PasswordNeverExpires')
	$allADUsers = get-aduser -filter * -ResultSetSize $userConfiguration.adRecordSize -Properties $adProperties

	# Check each user and assign flag (if required)
	ForEach($user in $allADUsers){

		Add-Member -InputObject $user -MemberType 'NoteProperty' -Name 'DateAssessed' -value $dateAssessed -Force
		Add-Member -InputObject $user -MemberType 'NoteProperty' -Name 'Include' -value 1 -Force

	}

	$allADUsers | Export-Clixml -path ($outputObject.OutputFullName) -Force
	$outputObject
}
function get-snowIntelligenceADGroupMembership{
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'populations'
	$populationName = 'adGroupMemberships'
	
	#region Load Required Modules
	if ($null -eq (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory }
	#endregion
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$groupConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion
	
	#region Collect AD User Information
	Write-Verbose "GET: AD Users"
	$allADUsers = Get-ADUser -Filter * -ResultSetSize $groupConfiguration.adRecordSize  -properties MemberOf
	$adUserCount = 0
	$exportGroupMembers = ForEach ($adUser in $allADUsers) {
        Write-Verbose " - samAccountName: $($adUser.samAccountName)"
		$percentComplete = [int] (($adUserCount/$allADUsers.Count) * 100)
		$statusActivity = "$adUserCount of $($allADUsers.count)"
		Write-Progress -Activity "Define User Membership Output" -PercentComplete $percentComplete -Status $statusActivity
		
		ForEach ($group in $adUser.MemberOf) {
			$groupName = $group.split(',')[0].trimStart('CN=')
			
			$diagOutputProperties = @{
				DateAssessed	   = $dateAssessed
				Include		       = 1
				groupName		   = $groupName
				groupDN		       = $group
				samAccountName     = $adUser.samAccountName
				userSID		       = $adUser.SID.value
			}
			$diagOutput = New-Object psObject -Property $diagOutputProperties
			$diagOutput.psobject.TypeNames[0] = 'snowIntelligence.Group.Member'
			$diagOutput
		}
		$adUserCount++
	}
	
	$exportGroupMembers | Export-Clixml -path ($outputObject.OutputFullName)
    $outputObject
    #endRegion


}

### PEOPLE FUNCTIONS ###
function get-snowIntelligencePeopleInventory{
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	$scriptType = 'populations'
	$populationName = 'people'
	
	#region Load Required Modules
	    # No Additional Modules Required
	#endregion

	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if((test-path $configurationFile) -eq $false){Write-Error "Unable to load configuration file $configurationFile";break}
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$peopleConfiguration = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion

	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion

    # Query the HR Database
    $peopleResults = invoke-sqlFunction -server $peopleConfiguration.hrServer -database $peopleConfiguration.hrDatabase -sql $peopleConfiguration.hrSQL
    forEach($person in $peopleResults){
        add-member -InputObject $person -MemberType 'NoteProperty' -name 'DateAssessed' -value $dateAssessed
    }

	$peopleResults | Export-Clixml -path ($outputObject.OutputFullName)
    $outputObject
}

### MEASUREMENT FUNCTIONS ###
function measure-snowIntelligencePercentCalulcation { 

	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)][string]$populationName,
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)][string]$measurementSource,
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 3)][string]$measurementVersion,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'measurements'
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$measurementConfig = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	
	#endRegion
	
	#region Collect Asset Information
    $numeratorResults = (invoke-sqlFunction -server ($measurementConfig.SQLServer) -database ($measurementConfig.Database) -sql $measurementConfig.Version.$measurementVersion.Numerator).Numerator

    $denominatorResults = (invoke-sqlFunction -server ($measurementConfig.SQLServer) -database ($measurementConfig.Database) -sql $measurementConfig.Version.$measurementVersion.Denominator).Denominator

	$measurementValue = [math]::Round($numeratorResults / $denominatorResults,2)

	$diagOutputProperties = @{
		DateAssessed = $dateAssessed
		Include = 1
		MeasurementID = $populationName
		MeasurementVersion = $measurementVersion
		MeasurementSource = $measurementSource
		MeasurementValue = $measurementValue
	}
	
	$diagOutput = New-Object psObject -Property $diagOutputProperties
	$diagOutput.psobject.TypeNames[0] = "snowIntelligence.Measurement"

	$diagOutput | Export-Clixml -path ($outputObject.OutputFullName)
	$outputObject



}

function measure-snowIntelligenceConfiguration {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)][string]$populationName,
		[parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 3)][string]$measurementVersion,
		[parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)][string]$configurationFile = $snowIntelligenceConfigPath
	)
	
	$scriptType = 'measurements'
	
	#region Load Configuration File
	Write-Verbose "BEGIN: Load Configuration File"
	if ((test-path $configurationFile) -eq $false) { Write-Error "Unable to load configuration file $configurationFile"; break }
	$snowIntelligenceConfiguration = get-content $configurationFile -Raw | ConvertFrom-Json
	$measurementConfig = $snowIntelligenceConfiguration.$scriptType.$populationName
	#endregion
	
	#region Define Output Information
	$outputObject = set-snowIntelligenceOutputInformation -scriptType $scriptType -name $populationName
	$dateAssessed = (Get-Date -Format 'yyyy-MM-dd HH:mm')
	#endRegion
	
	#region Collect Asset Information
    $results = invoke-sqlFunction -server ($measurementConfig.SQLServer) -database ($measurementConfig.Database) -sql $measurementConfig.Version.$measurementVersion.Query

	$output = forEach($result in $results){

		$diagOutputProperties = @{
			DateAssessed = $dateAssessed
			Include = 1
			MeasurementID = $populationName
			MeasurementVersion = $measurementVersion
			MeasurementSource = $result.MeasurementSource
			MeasurementValue = $result.MeasurementValue
		}
		
		$diagOutput = New-Object psObject -Property $diagOutputProperties
		$diagOutput.psobject.TypeNames[0] = "snowIntelligence.Measurement.$populationName"
		$diagOutput
	}
	$output | Export-Clixml -path ($outputObject.OutputFullName)
	$outputObject
}




Export-ModuleMember -Function *
Write-Verbose "Please run 'set-snowIntelligenceConfiguration' to set default configuration path for all functions" -Verbose

