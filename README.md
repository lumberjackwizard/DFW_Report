This PowerShell script generates an HTML output file of an NSX policy. Since the NSX Manager is only queried using GET requests, this script can’t make any actual changes to a given NSX environment. The account needs read-only access; the built-in ‘Audit’ account will suffice.

This script was built using PowerShell 7.4.5+. To execute, you can use: pwsh ./dfw_report.ps1 or execute it from within a PowerShell shell with just: ./dfw_report.ps1

When executed, the script prompts for the NSX Manager, username, and password. Once this is done, the user is prompted to enter a calendar date in YYYY-MM-DD format or press ‘Enter’ to get all policies and associated items regardless of the creation date.

The data is output in a single file called ‘output.html’.

There’s a single command parameter, -TestMode. When you execute the command with this parameter (pwsh ./dfw_report.ps1 -TestMode), the NSX Server, username, and password will be obtained from a local CSV file named “testdata.csv”. The CSV file structure should have a header line with the following:

nsxmgr,Username,Password

Then, there should be a second line with the NSX Manager FQDN/IP, username, and password. Since the password is stored in plain text, this is intended for testing only.
