#Created using PowerShell 7.4.5

# Temporarily hard setting nsxmgr and credentials for development. Get-Credential will be used in the future. 

$nsxmgr = '172.16.10.11'
$nsxuser = 'admin'
$nsxpasswd = ConvertTo-SecureString -String 'VMware1!VMware1!' -AsPlainText -Force
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $nsxuser, $nsxpasswd

#$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
#$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'

# Uri will get only securitypolices, groups, context profiles and services under infra


$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;Service;'


#This is formatting data for the later creation of the html file 

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


# The below gathers all securitypolicies, groups, and services from infra, storing it in 
# the $rawpolicy variable 

Write-Host "Requesting data from target NSX Manager..."

$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred 

# inserting logic so i can see how many lines are in the base $rawpolicy

# Convert $rawpolicy to JSON string
$rawPolicyJson = $rawpolicy | ConvertTo-Json -Depth 10

# Split JSON string into lines and count the number of lines
$lineCount = ($rawPolicyJson -split "`n").Count

Write-Host "Number of lines in the JSON string: $lineCount"


# Gathering security policies

Write-Host "Gathering DFW Security Policies and rules..."

$secpolicies = $rawpolicy.children.Domain.children.SecurityPolicy | Where-object {$_.id -And $_.id -ne 'Default'} | Sort-Object -Property internal_sequence_number



# Gathering Groups

Write-Host "Gathering Groups..."

$allgroups = $rawpolicy.children.Domain.children.Group | Where-object {$_.id}


Write-Host "Gathering Serivces..."

$allservices = $rawpolicy.children.Service | Where-object {$_.id}


# Gathering Context Profiles

Write-Host "Gathering Context Profiles..."

$allcontextprofiles = $rawpolicy.children.PolicyContextProfile | Where-object {$_.id}

# Gathering Tags
$alltags = $rawpolicy.children.Tags | Where-Object {$_.id}




function Generate_Breakdown_Report {
	

	$policy_count = 0
	$rule_count = 0
	foreach ($secpolicy in $secpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}) {
		$policy_count++
		foreach ($rule in $secpolicy.children.Rule){
			$rule_count++
		}
	}

	$svc_count = 0
	foreach ($svc in $allservices | Where-Object {$_.is_default -eq $False}){
		$svc_count++
	}

	$cxt_pro_count = 0
	foreach ($cxt_pro in $allcontextprofiles | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
		$cxt_pro_count++
	}

	$group_count = 0
	foreach ($grp in $allgroups | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
		$group_count++
	}

	$report_counts = @($policy_count,$rule_count,$svc_count,$cxt_pro_count,$group_count)


	return $report_counts
}


function Generate_Policy_Report {

	
	#NEW ATTEMPT#

	

	# Loop through the data to create rows with conditional formatting
	foreach ($secpolicy in $secpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}) {
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
			<td colspan=6></td>
		</tr>`n"

		
	
	# Gathering all rules and polices

		
		$sortrules = $secpolicy.children.Rule | Sort-Object -Property sequence_number
	
		$rowCount = 0
		foreach ($rule in $sortrules | Where-object {$_.id}){
			
			
			$ruleentryname = $rule.display_name
			$ruleentryaction = $rule.action
	
			$ruleentrysrc = ""
			$ruleentrydst = ""
			$ruleentrysvc = ""
			$ruleentrycxtpro = ""

			foreach ($srcgroup in $rule.source_groups){
				$n = 0
				foreach ($filteredgroup in $allgroups){
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
				foreach ($filteredgroup in $allgroups){
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
				foreach ($filsvc in $allservices){
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
				foreach ($filctxpro in $allcontextprofiles){
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

# The below code works, but still evaluating if there's a benefit to re-inserting the headers after 'x' 
# number of rows. Right now, this evaulation happens within each policy, so it's rows (aka rules) in the 
# policy, and not overall rows. 

# 			if ($rowCount -gt 0 -and $rowCount % 20 -eq 0) {
# 				# Insert the header again after every 20 rows
# 				$html_policy += @"
# 				<tr>
# 					<th>Category</th>
# 					<th>Security Policy Name</th>
# 					<th>Rule Name</th>
# 					<th>Source Groups</th>
# 					<th>Destination Groups</th>
# 					<th>Services</th>
# 					<th>Context Profiles</th>
# 					<th>Action</th>
# 				</tr>
# "@
# 			}
				
			$rowCount++
			#Write-Host $rowCount
				

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
			<td style='vertical-align: middle;'>$($ruleentryaction)</td>
			</tr>`n"
			
			
		}  
	}

	


   
	return $html_policy
}




function New-NSXLocalInfra {

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
        <span style="font-size:22px;"><strong><u>Segmentation Report</u></strong></span>
    </p>
    <p>&nbsp;</p>
    <table style="width: 60%; margin: 0 auto; border-collapse: collapse; font-size: 16px;">
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of Distributed Firewall Security Policies <i>(excluding system generated)</i>:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[0])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of Distributed Firewall Rules <i>(excluding system generated)</i>:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[1])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of User Created Services:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[2])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of User Created Context Profiles:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[3])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px;">Number of User Created Groups:</td>
            <td style="padding: 10px; text-align: right;"><b>$($report_counts[4])</b></td>
        </tr>
    </table>
	<p>&nbsp;</p>
	<p style="text-align:center;"><span style="font-size:18px;"><strong><u>Security Policies and associated rules (excluding system generated)&nbsp;</u></strong></span></p>
	<table>
		<thead>
			<tr>
				<th>Category</th>
				<th>Security Policy Name</th>
				<th>Rule Name</th>
				<th>Source Groups</th>
				<th>Destination Groups</th>
				<th>Services</th>
				<th>Context Profiles</th>
				<th>Action</th>
			</tr>
		</thead>
		<tbody>
"@


		$html += $html_policy


		#close the security policies  table
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



$html_policy = Generate_Policy_Report

$report_counts = Generate_Breakdown_Report
New-NSXLocalInfra







