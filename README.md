Powershell script to generate an html output file of an NSX policy. As the NSX Manager is only queried using GET requests, this script cannot make any actual changes to a given NSX environment. The account needs read-only access; to that end, the built-in 'Audit' account will suffice. 

This script was built using Powershell 7.4.5+. To execute, may use: pwsh ./dfw_report.ps1 or you can execute it from within a Powershell shell with just: ./dfw_report.ps1

When executed, the script will prompt for NSX Manager, Username, and Password. Once this is completed, the user is prompted to enter a calendar date in YYYY-MM-DD format or to simply hit 'Enter'. 
- Entering a specific date will gather all policies and associated items that have been created on or after the entered calendar date.
- Entering no date at all will gather ALL policies and associated items, regardless of creation date

The data is output in a single file called 'output.html. 


There is a single command parameter that can be utilized, which is -TestMode. When the command is executed with this parameter (pwsh ./dfw_report.ps1 -TestMode), the NSX Server, User, and Password will be obtained from a local csv file that must be named "testdata.csv". The structure of the csv file should be a header line comprised of the following:

nsxmgr,Username,Password

Followed by a second line that contains the NSX Manager FQDN/IP, username, and password. Obviously, as the password is stored in clear text, this is intended for test uses only. 