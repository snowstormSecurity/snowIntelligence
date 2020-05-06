# Purpose
The snowIntelligence PowerShell module was designed to provide a framework to collect various aspects of security in a corporate environment.  The results can then be used to calculate measurements of the state of security within the environment.  

The framework is geared to allow IT and Security staff to write their own scripts to collect and measure security aspects.  The existing configuration file, and scripts, serve as an example.


# Requirements
For this module to function, the following items are required:
## SQL Database
A Microsoft SQL database is required.  While `sa` rights are required to build the database, only CREATE, SELECT, INSERT, DELETE, DROP table rights are required after the database is setup.

## PowerShell Remote Capabilities
While many of the scripts require the ability to remotely connect to target systems, this is mostly required.  If you have the ability to extract the information from the target via another method (e.g. scheduled export to CSV) the `convert-CSVtosnowIntelligenceXML` function will convert any CSV file into the proper import format.

# Usage
The steps to setup snowIntelligence are:
1. Create a database on a MS SQL system
   1. Grant the required permissions to CREATE & DROP Tables
   2. Grant the required permissions to run SELECT, INSERT, DELETE on the tables
2. Update the [/config/snowIntelligence.json](config/snowIntelligence.json) configuration file with information on the location of the SQL server and Database
3. Create Script (or use existing examples) to pull information into the environment.
4. Run Collection Processes (see examples in [start-dailyCollection.example.ps1](bin/start-dailyCollection.example.ps1))
5. Based on the type of data being collected, define measurements in the [/config/snowIntelligence.json](config/snowIntelligence.json).
6. Connect PowerBI to the SQL dataset
7. Establish Relationships
8. Build Reports


