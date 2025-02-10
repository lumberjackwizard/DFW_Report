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
		} elseif ($secpolicy.category -eq "Ethernet") {
			$rowStyle = ' style="background-color: #6F869E; "' 
		} elseif ($secpolicy.category -eq "Emergency") {
			$rowStyle = ' style="background-color: #C74C4C; "' 
		}
    
		#logic to add applied to notation to applicable policy
		$policy_Applied_To = $null

		if ($secpolicy.scope -ne "ANY"){
			$policy_Applied_To = "<i>* 'Applied To' is configured for this Security Policy, and all rules within this policy inherit these settings</i>"
		}
	
		# Add the row to the HTML
		$html_policy += "    <tr$rowStyle>
			<td style='font-weight: bold;'>$($secpolicy.category)</td>
			<td>$($secpolicy.display_name)</td>
			<td colspan=7>$($policy_Applied_To)</td>
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

			
			if ($secpolicy.scope -ne "ANY"){
				$ruleentryappliedto = ((($allsecgroups | Where-Object {$_.path -in $secpolicy.scope}).display_name | Foreach-Object { "$_*" }) -join "`n")
			} else {
				$ruleentryappliedto = (($allsecgroups | Where-Object {$_.path -in $rule.scope}).display_name -join "`n")
				if (-not $ruleentryappliedto) {
					$ruleentryappliedto = "DFW"
				}
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
				$rowStyle2 = ' style="background-color: #C4C4C4;"'
			} else { 
				$rowStyle2 = ' style="background-color: #AEB6BC;"'
			}

			# Adding logic to alter the colors of the first two columns depending on the policy category

	
			if ($secpolicy.category -eq "Infrastructure") {
				$nullStyle = ' style="background-color: #6BAC82; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Environment") {
				$nullStyle = ' style="background-color: #6FA3D1; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Application") {
				$nullStyle = ' style="background-color: #DBACFC; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Ethernet") {
				$nullStyle = ' style="background-color: #98AFC4; border-bottom: none; border-top: none;" colspan=2></td' 
			} elseif ($secpolicy.category -eq "Emergency") {
				$nullStyle = ' style="background-color: #E07A7A; border-bottom: none; border-top: none;" colspan=2></td' 
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
		<p>
        This report was generated using <b>Targeted Mode</b> with a start date of <b>$($startDate[0])<\b>.
		Security Polices and associated objects created on or after this date will be included. 
    	</p>
"@
	} else {

		@"
		<p>
        This report was generated using <b>Targeted Mode</b>. All Security Policies and associated objects are 
		included in this report, regardless of creation date. 
    	</p>
"@


	}

	Write-Host "Generating output file..."

	$today = Get-Date -Format "dddd, MMMM dd, yyyy"

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
        <span style="font-size:22px;"><strong>Professional Services vDefend Segmentation Report</strong></span>
    </p>
	<p style="text-align:center;">
        <span style="font-size:18px;"><strong>Report Creation Date -  $($today)</strong></span>
    </p>

	<br>
	<section>
    	<h3><u>Introduction</h3></u>
		<p>
			This report provides a <strong>clear and structured overview</strong> of user-created security policies and firewall rules within your environment. 
			It is designed to help you understand your current security configurations, how firewall rules are applied, and the objects associated with these policies.
		</p>

		<p>To ensure clarity, the report is divided into the following sections:</p>

		<ul>
			<li>
				<strong>Report Capture Modes</strong> – Explains how the data was collected, whether as a 
				<em>complete snapshot of all user-created policies</em> or a 
				<em>targeted view of policies created after a specific date</em>. 
				The mode used for this report is noted in this section.
			</li>
			<li>
				<strong>Security Policy and Firewall Rule Summary</strong> – Highlights the total number of 
				<em>user-created security policies and firewall rules</em>, grouped by category. 
				It also includes a summary of <em>services, context profiles, and groups</em> that support these rules.
			</li>
			<li>
				<strong>Firewall Policy Overview</strong> – Provides a <em>snapshot of the firewall policy</em> at the time of reporting, 
				ensuring transparency into the current security setup. 
				<strong>System-owned policies and objects are excluded</strong>, so the report focuses solely on configurations created by users.
			</li>
		</ul>

		<p>
			This report is designed to give you <strong>a clear view of your security policies and firewall rules</strong>, 
			helping you manage and optimize your security posture with confidence.
    </p>
	</section>
	<section>
		<h3><u>Report Capture Modes</h3></u>
		<p>
			This report operates in two distinct modes:
		</p>
		
		<ul>
			<li><strong>Complete Mode</strong> – Captures <em>all user-created security policies, firewall rules, and objects</em>, regardless of their creation time.</li>
			<li><strong>Targeted Mode</strong> – Captures <em>only user-created policies and objects that were created after a specified date</em>, providing a focused view of recent security changes.</li>
		</ul>

		<p>The selected mode determines the scope of the data presented in this report.</p>

    	$dateLine

	</section>

	
	<section>
		<h3><u>Security Policy and Firewall Rule Summary</u></h3>
		<p>
			This section provides an overview of <strong>user-created security policies, firewall rules, and associated distributed firewall objects</strong> within the environment. 
			It details the total number of <strong>security policies</strong> configured across various categories, including 
			<em>Ethernet, Emergency, Infrastructure, Environment, and Application</em>.
		</p>
		
		<p>
			Additionally, it highlights the <strong>distribution of firewall rules</strong> across these categories, 
			offering insights into policy enforcement and segmentation. The section also includes a summary of 
			<strong>user-defined distributed firewall objects</strong>, such as <em>services, context profiles, and groups</em>, 
			which support rule implementation.
		</p>
		
		<p><strong>Note:</strong> This summary <em>excludes system-owned policies and objects</em> and only accounts for security configurations explicitly created by users.</p>
	</section>



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

	
	<section>
    <h3><u>Firewall Policy Overview</h3></u>
    <p>
        This section presents a <strong>snapshot of the entire firewall policy</strong> as it was captured at the time of reporting. 
        It includes a comprehensive overview of all <strong>user-created security policies, firewall rules, and associated objects</strong>, 
        providing insight into the current configuration and policy structure.
    </p>
    
	<p>
		
        With <strong>DFW policies and rules</strong>, the <strong>'Applied To'</strong> setting can be configured 
        <em>directly on an individual rule</em> or <em>overridden at the Security Policy level</em>. 
        In the <strong>section below</strong>, when <strong>'Applied To'</strong> is set at the 
        <strong>Security Policy level</strong>, a notation appears in the <strong>Policy Name</strong> 
        section, and an <strong>asterisk (*)</strong> is placed beside the group(s) in the 
        <strong>'Applied To'</strong> field for each rule within the policy.
    </p>

    <p>
        It is important to note that in the <strong>NSX UI</strong>, the <strong>'Applied To'</strong> setting 
        can still be configured at the <em>rule level</em>, even when a <em>Security Policy-level 'Applied To'</em> exists. 
        However, in this case, the <em>rule-level setting is purely cosmetic</em> and is fully 
        <strong>overridden by the Security Policy's configuration</strong>.
    </p>

    <p>
        Therefore, the information below reflects the <strong>effective 'Applied To' configuration</strong>, 
        not the <em>cosmetic UI representation</em>.
    </p>
	
    <p><strong>Note:</strong> System-owned policies are <em>excluded</em> from this report, ensuring that only user-defined security configurations are represented.</p>
</section>



	<p>&nbsp;</p>
	<table style="width: 10%; border-collapse: collapse; font-size: 12px; border: 2px solid #000;">
		<thead>
			<tr>
				<th style="padding: 10px; border-bottom: 1px solid #ccc; background-color: #333; color: white;" colspan="2">Legend</th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc;">Ethernet</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: center; background-color: #6F869E; width: 40px;">&nbsp;</td>
			</tr>
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #ccc;">Emergency</td>
				<td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: center; background-color: #C74C4C; width: 40px;">&nbsp;</td>
			</tr>
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







