# snowIntelligence.json
The json configuration file is broken down into three major sections

## General
The **General** section defines where the snowIntelligence should store, and search for XML files.
| Property | Purpose|
|-|-|
|Output|This is the root folder that snowIntelligence|
|Results| This is the subfolder where snowIntelligence expects to find results.|
|Raw|If results need processing between being exported from the collection script, and being imported they should be placed in the appropriate **Raw** folder|
|Processed|Once the import process has successfully added records to the database, it will move the XML file to the appropriate *Processed* folder|
|errorFolder|If the import process detects an error, the process will move the XML file to the appropriate *errorFolder*|

## Populations
The section is geared towards defining where the collection of data is to be stored within the SQL database, along with any required properties to collect the data.  In general, each Population entry must have:
|Property|Purpose|
|-|-|
|SQLServer|The name of the system hosting the SQL database|
|Database|The name of the database|
|Table|The name of the table|

If you create a script that may require different variables, you can extend the specific population item with variables that can be pulled into the script.  This allows for a single script to be run across multiple configurations

## Measurements
Like the Populations, the Measurements section defines where the measurements should be stored in the SQL database.  It is also used to define *how* the measurements should be defined.  Because determining proper calculations can be a complicated process, each measurement entry is expected to have multiple versions.  This allows the analyst the ability to run multiple calculations on a single security aspects and have all the results stored within the database.

