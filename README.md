Powershell script to generate an html output file of an NSX policy. As the NSX Manager is only queried using GET requests, this script cannot make any actual changes to a given NSX environment. The account needs read-only access; to that end, the built-in 'Audit' account will suffice. 

When executed, the script will prompt for NSX Manager, Username, and Password. Once this is completed, the user is prompted to enter a calendar date in YYYY-MM-DD format or to simply hit 'Enter'. 
- Entering a specific date will gather all policies and associated items that have been created on or after the entered calendar date.
- Entering no date at all will gather ALL policies and associated items, regardless of creation date

The data is output in a single file called 'output.html. 
