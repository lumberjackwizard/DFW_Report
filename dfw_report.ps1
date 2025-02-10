#Created using PowerShell 7.4.5

param (
    [switch]$TestMode
)



function Invoke-CheckNSXCredentials(){
	$checkUri = 'https://'+$nsxmgr+'/policy/api/v1/infra'

	#using Invoke-WebRequst to evaluate the statuscode that is returned from the NSX Manager
	$response = Invoke-WebRequest -Uri $checkUri -Method Get -SkipCertificateCheck -Authentication Basic -Credential $Cred -SkipHttpErrorCheck
	
	if ($response.StatusCode -eq 200) {
		Write-Host "Successfully connected to NSX Manager. Status: 200 OK"
	} else {
		Write-Host "Failed to connect to NSX Manager." 
		Write-Host "Status: $($response.StatusCode)"
		Write-Host "Error Message:" ($response.Content)
		Write-Host "Exiting script... Please try again. "
		exit
	}

}

function Get-NSXDFW(){

	# The below gathers all securitypolicies, groups, and services from infra, storing it in 
	# the $rawpolicy variable 

	Write-Host "Requesting data from target NSX Manager..."

	$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
	$rawservices = Invoke-RestMethod -Uri $SvcUri -SkipCertificateCheck -Authentication Basic -Credential $Cred 

	# Gathering security policies

	Write-Host "Gathering DFW Security Policies and rules..."

	$secpolicies = $rawpolicy.children.Domain.children.SecurityPolicy | Where-object {$_.id -And $_.id -ne 'Default'} | Sort-Object -Property internal_sequence_number

	# Gathering Groups

	Write-Host "Gathering Groups..."

	$allgroups = $rawpolicy.children.Domain.children.Group | Where-object {$_.id}


	Write-Host "Gathering Serivces..."

	$allservices = $rawservices.children.Service | Where-object {$_.id}


	# Gathering Context Profiles

	Write-Host "Gathering Context Profiles..."

	$allcontextprofiles = $rawpolicy.children.PolicyContextProfile | Where-object {$_.id}

	return [pscustomobject]@{
        SecPolicies =        $secpolicies
		AllGroups   =        $allgroups
		AllServices =        $allservices
		AllContextProfiles = $allcontextprofiles
    }

}

function Get-StartDate {
	# While loop runs until a date is succesfully entered in the proper format
	while ($true) {
		# Prompt user for a calendar date
		Write-Host "`n"
		$dateInput = Read-Host "Enter a calendar date in YYYY-MM-DD format (ex., 2024-11-18) or just hit Enter to gather all polices"

		if ($dateInput -match '^\d{4}-\d{2}-\d{2}$') {
			try {
				# Parse the entered date into a DateTime object
				$parsedDate = [DateTime]::Parse($dateInput)

				# Get the epoch timestamp in milliseconds
				$epochMilliseconds = [DateTimeOffset]::new($parsedDate).ToUnixTimeMilliseconds()

				# Return the results

				$dates = @($dateInput,$epochMilliseconds)
				#return $epochMilliseconds
				return $dates
			}
			catch {
				
				Write-Host "Invalid date: $dateInput. Please enter a valid date in YYYY-MM-DD format."
			}
		} elseif ($dateInput -eq ""){

			$dates = @($dateInput,$epochMilliseconds)
			return $dates
			#return $epochMilliseconds
			Write-Host "No date entered; all Policies will be gathered"

		} else {
			Write-Host "Invalid format. Please enter a date in YYYY-MM-DD format."
		}
	}
}
function Invoke-GenerateBreakdownReport {
	
	$eth_category = 0
	$emer_category = 0
	$infra_category = 0
	$env_category = 0
	$app_category = 0
	$policy_count = 0
	$rule_count = 0
	$eth_rule_count = 0
	$emer_rule_count = 0
	$infra_rule_count = 0
	$env_rule_count = 0
	$app_rule_count = 0

	foreach ($secpolicy in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False -And $startDate[1] -le $_._create_time}) {
		$policy_count++
		if ($secpolicy.category -eq "Infrastructure") {
        	$infra_category++
			foreach ($rule in $secpolicy.children.Rule){
				$infra_rule_count++
			}
    	} elseif ($secpolicy.category -eq "Environment") {
			$env_category++
			foreach ($rule in $secpolicy.children.Rule){
				$env_rule_count++
			}
		} elseif ($secpolicy.category -eq "Application") {
			$app_category++
			foreach ($rule in $secpolicy.children.Rule){
				$app_rule_count++
			}
		} elseif ($secpolicy.category -eq "Ethernet") {
			$eth_category++
			foreach ($rule in $secpolicy.children.Rule){
				$eth_rule_count++
			}
		} elseif ($secpolicy.category -eq "Emergency") {
			$emer_category++
			foreach ($rule in $secpolicy.children.Rule){
				$emer_rule_count++
			}
		}
		foreach ($rule in $secpolicy.children.Rule){
			$rule_count++
		}
	}

	$svc_count = 0
	foreach ($svc in $allsecservices | Where-Object {$_.is_default -eq $False -And $startDate[1] -le $_._create_time}){
		$svc_count++
	}

	$cxt_pro_count = 0
	foreach ($cxt_pro in $allseccontextprofiles | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False -And $startDate[1] -le $_._create_time}){
		$cxt_pro_count++
	}

	$group_count = 0
	foreach ($grp in $allsecgroups | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False -And $startDate[1] -le $_._create_time}){
		$group_count++
	}

	$report_counts = @($policy_count,$rule_count,$svc_count,$cxt_pro_count,$group_count,$infra_category,$env_category,$app_category,$infra_rule_count,$env_rule_count,$app_rule_count,$eth_category,$emer_category,$eth_rule_count,$emer_rule_count)


	return $report_counts
}

function Invoke-GeneratePolicyReport {

	
	# Loop through the data to create rows with conditional formatting
	foreach ($secpolicy in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False -And $startDate[1] -le $_._create_time}) {
		
    # Ensure that lines that contain the category and policy are a unique color compared to the rows that have rules
	
    	$rowStyle = ''
    	if ($secpolicy.category -eq "Infrastructure") {
        	$rowStyle = ' style="background-color: #2F8A4C; "' 
    	} elseif ($secpolicy.category -eq "Environment") {
			$rowStyle = ' style="background-color: #4682B4; "' 
		} elseif ($secpolicy.category -eq "Application") {
			$rowStyle = ' style="background-color: #995CD5; "' 
		}
    
    # Add the row to the HTML
		$html_policy += "    <tr$rowStyle>
			<td style='font-weight: bold;'>$($secpolicy.category)</td>
			<td>$($secpolicy.display_name)</td>
			<td colspan=7></td>
		</tr>`n"

		
	
	# Gathering all rules and polices

		
		$sortrules = $secpolicy.children.Rule | Sort-Object -Property sequence_number

		
	
		$rowCount = 0
		foreach ($rule in $sortrules | Where-object {$_.id}){
			
			$ruleentryname = $rule.display_name
			$ruleentryaction = $rule.action
			#Each of the next five actions are taking the data from a field in the rule and then comparing it to security groups, services, or context
			#profiles to get the more human readable "display name". The "if" statements are there if and when the rule has an 'ANY', which won't 
			#match the existing query. Context Profiles are deliberately blank in this situation for readability. 
			$ruleentrysrc = (($allsecgroups | Where-Object {$_.path -in $rule.source_groups}).display_name -join "`n")
			if (-not $ruleentrysrc) {
				$ruleentrysrc = "Any"
			}

			$ruleentrydst = (($allsecgroups | Where-Object {$_.path -in $rule.destination_groups}).display_name -join "`n")
			if (-not $ruleentrydst) {
				$ruleentrydst = "Any"
			}

			$ruleentrysvc = (($allsecservices | Where-Object {$_.path -in $rule.services}).display_name -join "`n")
			if (-not $ruleentrysvc) {
				$ruleentrysvc = "Any"
			}

			$ruleentrycxtpro = (($allseccontextprofiles | Where-Object {$_.path -in $rule.profiles}).display_name -join "`n")
			if (-not $ruleentrycxtpro) {
				$ruleentrycxtpro = ""
			}

			$ruleentryappliedto = (($allsecgroups | Where-Object {$_.path -in $rule.scope}).display_name -join "`n")
			if (-not $ruleentryappliedto) {
				$ruleentryappliedto = "DFW"
			}


			<# foreach ($srcgroup in $rule.source_groups){
				$n = 0
				foreach ($filteredgroup in $allsecgroups){
					if ($filteredgroup.path -eq $srcgroup){
						$ruleentrysrc += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrysrc += $srcgroup + "`n"
					}	
			} 


			
			
			foreach ($dstgroup in $rule.destination_groups){  
				$n = 0
				foreach ($filteredgroup in $allsecgroups){
					if ($filteredgroup.path -eq $dstgroup){
						$ruleentrydst += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrydst += $dstgroup + "`n"
				}
			}	

			foreach ($svcgroup in $rule.services){ 
				$n = 0
				foreach ($filsvc in $allsecservices){
					if ($filsvc.path -eq $svcgroup){
						$ruleentrysvc += $filsvc.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrysvc += $svcgroup + "`n"
				}							
			}
			
			
			foreach ($cxtprogroup in $rule.profiles){  
				$n = 0
				foreach ($filctxpro in $allseccontextprofiles){
					if ($filctxpro.path -eq $cxtprogroup){
						$ruleentrycxtpro += $filctxpro.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrycxtpro += $cxtprogroup + "`n"
				}
			}

			foreach ($appliedtogroup in $rule.scope){
				$n = 0
				foreach ($filteredgroup in $allsecgroups){
					if ($filteredgroup.path -eq $appliedtogroup){
						$ruleentryappliedto += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentryappliedto += $appliedtogroup + "`n"
					}	
			}
			#>
				
			$rowCount++
						
			# Add the row to the HTML
			if ($rowCount % 2) {
				$rowStyle2 = ' style="background-color: #B0C4DE;"'
			} else { 
				$rowStyle2 = ' style="background-color: #949BAF;"'
			}

			# Adding logic to alter the colors of the first two columns depending on the policy category

	
			if ($secpolicy.category -eq "Infrastructure") {
				$nullStyle = ' style="background-color: #6BAC82; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Environment") {
				$nullStyle = ' style="background-color: #6FA3D1; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Application") {
				$nullStyle = ' style="background-color: #DBACFC; border-bottom: none; border-top: none;" colspan=2></td' 
			}
	
		#<td style='background-color: #6BAC82; border-bottom: none; border-top: none;' colspan=2></td>

			$html_policy += "    <tr$rowStyle2>
			<td$nullStyle>
			<td style='vertical-align: middle;'>$($ruleentryname)</td>
			<td style='vertical-align: middle;'>$($ruleentrysrc)</td>
			<td style='vertical-align: middle;'>$($ruleentrydst)</td>
			<td style='vertical-align: middle;'>$($ruleentrysvc)</td>
			<td style='vertical-align: middle;'>$($ruleentrycxtpro)</td>
			<td style='vertical-align: middle;'>$($ruleentryappliedto)</td>
			<td style='vertical-align: middle;'>$($ruleentryaction)</td>
			</tr>`n"
			
			
		}  
	}

	


   
	return $html_policy
}

function Invoke-OutputReport {


	$dateLine = if ($startDate[1]) {

		@"
		<p style="text-align:center;">
        <span style="font-size:18px;"><strong><u>vDefend Distributed Firewall - User Created Security Policy - Summaries $($startDate[0])</u></strong></span>
    	</p>
"@
	} else {

		@"
		<p style="text-align:center;">
        <span style="font-size:18px;"><strong><u>vDefend Distributed Firewall - Complete User Created Security Policy - Summaries</u></strong></span>
    	</p>
"@


	}

	Write-Host "Generating output file..."

	# Start the HTML 
	$html = @"

	<html>
	<head>
	$header
	</head>
	<body>
	<div>
        <img src="logo.png" alt="Logo" class="logo">
    </div>
	<p style="text-align:center;">
        <span style="font-size:22px;"><strong>vDefend Segmentation Report</strong></span>
    </p>

    $dateLine

    <br>
    <table style="width: 60%; margin: 0 auto; border-collapse: collapse; font-size: 16px; border: 2px solid #000;">
		<thead>
			<tr>
				<th style="padding: 12px; border-bottom: 3px solid #000; border-top: 3px solid #000; background-color: #A9A9A9; text-align: center; font-weight: bold; font-size: 14px;" colspan="2">Security Policies - Summary</th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Distributed Firewall Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;text-align: right;"><b>$($report_counts[0])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Ethernet Category Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[11])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Emergency Category Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[12])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Infrastructure Category Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[5])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Environment Category Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[6])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Application Category Security Policies:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[7])</b></td>
			</tr>
		</tbody>
	</table>	
	<br>
	<table style="width: 60%; margin: 0 auto; border-collapse: collapse; font-size: 16px; border: 2px solid #000;">
		<thead>
			<tr>
				<th style="padding: 12px; border-bottom: 3px solid #000; border-top: 3px solid #000; background-color: #A9A9A9; text-align: center; font-weight: bold; font-size: 14px;" colspan="2">Distributed Firewall Rules - Summary</th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[1])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Ethernet Category Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[13])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Emergency Category Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[14])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Infrastructure Category Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[8])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Environment Category Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[9])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Application Category Distributed Firewall Rules:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[10])</b></td>
			</tr>
		</tbody>
	</table>
	<br>
	<table style="width: 60%; margin: 0 auto; border-collapse: collapse; font-size: 16px; border: 2px solid #000;">
		<thead>
			<tr>
				<th style="padding: 12px; border-bottom: 3px solid #000; border-top: 3px solid #000; background-color: #A9A9A9; text-align: center; font-weight: bold; font-size: 14px;" colspan="2">Associated Distributed Firewall Objects - Summary</th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Services:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[2])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Context Profiles:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[3])</b></td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc;">Total Number of User Created Groups:</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; border-top: 1px solid #ccc; text-align: right;"><b>$($report_counts[4])</b></td>
			</tr>
		</tbody>
    </table>
	<p>&nbsp;</p>

	
	<p style="text-align:center;"><span style="font-size:18px;"><strong><u>vDefend Distributed Firewall - User Created Policy Snapshot</u></strong></span></p>
	


	<p>&nbsp;</p>
	<table style="width: 10%; border-collapse: collapse; font-size: 12px; border: 2px solid #000;">
		<thead>
			<tr>
				<th style="padding: 10px; border-bottom: 1px solid #ccc; background-color: #333; color: white;" colspan="2">Legend</th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc;">Infrastructure</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: center; background-color: #2F8A4C; width: 40px;">&nbsp;</td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc;">Environment</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: center; background-color: #4682B4; width: 40px;">&nbsp;</td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc;">Application</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: center; background-color: #995CD5; width: 40px;">&nbsp;</td>
			</tr>
		</tbody>
	</table>
	
	<br>


	
	<table style="border: 2px solid #000;" >
		<thead>
			<tr>
				<th>Category</th>
				<th>Security Policy Name</th>
				<th>Rule Name</th>
				<th>Source Groups</th>
				<th>Destination Groups</th>
				<th>Services</th>
				<th>Context Profiles</th>
				<th>Applied To</th>
				<th>Action</th>
			</tr>
		</thead>
		<tbody>
"@


		$html += $html_policy


		#close the security policies table
		$html += @"
		</tbody>
		<tfoot>
			<tr style="border-top: 2px solid black;"></tr>
		</tfoot>
		</table>
		<p>&nbsp;</p>
		<p>&nbsp;</p>
		<p>&nbsp;</p>
		</body>
		</html>
"@
	
	$html | Set-Content -Path 'output.html'  # Save to an HTML file

}


##########################
# Main
##########################

# If "-TestMode" is appended as a command switch to the script, the nsx server, username, and password are pulled
# from a local 'testdata.csv' file. This allows for running the script with automated credentials during testing. 


if ($TestMode) {
    $Config = Import-Csv "testdata.csv"
	$nsxmgr = $Config.nsxmgr
    $nsxuser = $Config.Username
    $nsxpasswd = ConvertTo-SecureString -String $Config.Password -AsPlainText -Force
	$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $nsxuser, $nsxpasswd
} else {

$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'
}

# Uri will get only securitypolices, groups, and context profiles under infra
# SvcUri will get only services under infra

$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;'
$SvcUri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=Service;'



Invoke-CheckNSXCredentials

$startDate = Get-StartDate

$allpolicies = Get-NSXDFW



$allsecpolicies = $allpolicies.SecPolicies
$allsecgroups = $allpolicies.AllGroups
$allsecservices = $allpolicies.AllServices
$allseccontextprofiles = $allpolicies.AllContextProfiles


#$header is formatting data for the the html file that will be created

$header = @"
<style>
table {
font-size: 14px;
border-collapse: collapse;
width: 100%; 
font-family: Arial, Helvetica, sans-serif;
} 

    td {
padding: 4px;
margin: 0;
border: 1px solid #4d4d4d;
word-wrap: break-word;
overflow-wrap: break-word;
white-space: pre-wrap;
max-width: 300px;
}

    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
		border: 1px solid #4d4d4d;
}


	td:nth-child(1), th:nth-child(1),
	td:nth-child(2), th:nth-child(2) {
    font-weight: bold;                   /* Makes text bold for the first two columns */
	}

        #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }

.logo {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 200px; /* Adjust size as needed */
            height: auto;
        }
    
</style>
"@

$html_policy = " "



$html_policy = Invoke-GeneratePolicyReport

$report_counts = Invoke-GenerateBreakdownReport


#final function to create output file
Invoke-OutputReport







