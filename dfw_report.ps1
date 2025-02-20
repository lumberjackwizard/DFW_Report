#Created using PowerShell 7.4.5

param (
    [switch]$TestMode
)

#setting up timers to display how long steps take to complete
$scriptTimer = [System.Diagnostics.Stopwatch]::StartNew()
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()


function Invoke-CheckNSXCredentials(){
	if ($localOrGlobal -match "^[yY]$") {
		$checkUri = 'https://'+$nsxmgr+'/global-manager/api/v1/global-infra'
	} else {
		$checkUri = 'https://'+$nsxmgr+'/policy/api/v1/infra'
	}


	#using Invoke-WebRequst to evaluate the statuscode that is returned from the NSX Manager
	$response = Invoke-WebRequest -Uri $checkUri -Method Get -SkipCertificateCheck -Authentication Basic -Credential $Cred -SkipHttpErrorCheck
	
	if ($response.StatusCode -eq 200) {
		Write-Host "Successfully connected to NSX Manager $nsxmgr. Status: 200 OK"
	} else {
		Write-Host "Failed to connect to NSX Manager $nsxmgr." 
		Write-Host "Status: $($response.StatusCode)"
		Write-Host "Error Message:" ($response.Content)
		Write-Host "Exiting script... Please try again. "
		exit
	}

}

# Define the custom order for categories
$categoryOrder = @(
	"Ethernet", 
	"Emergency",
	"Infrastructure", 
	"Environment", 
	"Application"
)
function Get-NSXDFW(){

	# The below gathers all securitypolicies, groups, and services from infra, storing it in 
	# the $rawpolicy variable 

	Write-Host "Requesting data from target NSX Manager..."

	$stopwatch.Restart()

	$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
	$rawservices = Invoke-RestMethod -Uri $SvcUri -SkipCertificateCheck -Authentication Basic -Credential $Cred

	if ($localManagedByGlobal -match "^[yY]$") {
		$rawglobalpolicy = Invoke-RestMethod -Uri $globalUri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
		$rawglobalservices = Invoke-RestMethod -Uri $globalSvcUri -SkipCertificateCheck -Authentication Basic -Credential $Cred
	}



	Write-Host "API data gathered in $($stopwatch.Elapsed)"

	# Gathering security policies

	Write-Host "Identifying DFW Security Policies and rules..."
	$stopwatch.Restart()

	$secpolicies = $rawpolicy.children.Domain.children.SecurityPolicy.Where({$_.id})

	#The below is to try and sort the security polices without relying on pipelining to Sort-Object, as it's slow for large data sets
	# Convert to a .NET List
	$list = [System.Collections.Generic.List[PSCustomObject]]::new()
	# Convert each object in $secpolicies to PSCustomObject before adding
	@($secpolicies).ForEach({ $list.Add([PSCustomObject]$_) })
	# Sort in place using .NET's built-in Sort()
	$list.Sort([System.Comparison[PSCustomObject]]{
		param ($a, $b) 
		[int]$a.internal_sequence_number - [int]$b.internal_sequence_number
	})

	# Now $list is sorted
	$sortedSecPolicies = $list

	
	Write-Host "Security Polices and Rules identified in $($stopwatch.Elapsed) (HH:MM:SS:MS)"
	

	# Gathering Groups

	Write-Host "Identifying Groups..."
	$stopwatch.Restart()

	$allgroups = $rawpolicy.children.Domain.children.Group.Where({$_.id})
	if ($localManagedByGlobal -match "^[yY]$") {
		$allgroups += $rawglobalpolicy.children.Domain.children.Group.Where({$_.id})
	}

	# Creating a hashset for groups to be used during rule creation for html



	Write-Host "Groups identified in $($stopwatch.Elapsed) (HH:MM:SS:MS)"

	Write-Host "Identifying Serivces..."
	$stopwatch.Restart()

	$allservices = $rawservices.children.Service.Where({$_.id})
	if ($localManagedByGlobal -match "^[yY]$") {
		$allservices += $rawglobalservices.children.Service.Where({$_.id})
	}
	Write-Host "Services identified in $($stopwatch.Elapsed) (HH:MM:SS:MS)"

	# Gathering Context Profiles

	Write-Host "Identifying Context Profiles..."
	$stopwatch.Restart()

	$allcontextprofiles = $rawpolicy.children.PolicyContextProfile.Where({$_.id})
	if ($localManagedByGlobal -match "^[yY]$") {
		$allcontextprofiles += $rawglobalpolicy.children.PolicyContextProfile.Where({$_.id})
	}

	Write-Host "Context Profiles identified in $($stopwatch.Elapsed) (HH:MM:SS:MS)"


	return [pscustomobject]@{
        SecPolicies =        $sortedSecPolicies
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
				return $dates
			}
			catch {
				
				Write-Host "Invalid date: $dateInput. Please enter a valid date in YYYY-MM-DD format."
			}
		} elseif ($dateInput -eq ""){

			$dates = @($dateInput,$epochMilliseconds)
			return $dates
			Write-Host "No date entered; all Policies will be gathered"

		} else {
			Write-Host "Invalid format. Please enter a date in YYYY-MM-DD format."
		}
	}
}
function Invoke-GenerateBreakdownReport {
	

	Write-Host "Generating Report Summaries..."
	$stopwatch.Restart()
	#Gathering Category and Rule counts

	# Initialize counts
	$policy_count = 0
	$rule_count = 0

	# Hashtable for category and rule counts
	$categoryCounts = @{
		"Infrastructure" = 0
		"Environment"    = 0
		"Application"    = 0
		"Ethernet"       = 0
		"Emergency"      = 0
	}

	$ruleCounts = @{
		"Infrastructure" = 0
		"Environment"    = 0
		"Application"    = 0
		"Ethernet"       = 0
		"Emergency"      = 0
	}

	# Filter and process security policies
	$policy_count = $allsecpolicies.Where({$_._create_user -ne 'system' -And -not $_._system_owned -And $startDate[1] -le $_._create_time}).Count
	$rule_count = ($allsecpolicies.children.Rule).Count
	
	#Breaking down Polices by category and then calulating unique category rules
	$allsecpolicies.Where({
		$_._create_user -ne 'system' -And -not $_._system_owned -And $startDate[1] -le $_._create_time}).ForEach({
				$categoryCounts[$_.category]++
				$ruleCounts[$_.category] += ($_.children.Rule).Count
		})


	$eth_category = $($categoryCounts["Ethernet"])
	$emer_category = $($categoryCounts["Emergency"])
	$infra_category = $($categoryCounts["Infrastructure"])
	$env_category = $($categoryCounts["Environment"])
	$app_category = $($categoryCounts["Application"])
	$eth_rule_count = $($ruleCounts["Ethernet"])
	$emer_rule_count = $($ruleCounts["Emergency"])
	$infra_rule_count = $($ruleCounts["Infrastructure"])
	$env_rule_count = $($ruleCounts["Environment"])
	$app_rule_count = $($ruleCounts["Application"])

	#Gathering service counts
	$svc_count = $allsecservices.Where({-not $_.is_default -And $startDate[1] -le $_._create_time}).Count

	#Gathering context profile counts
	$cxt_pro_count = $allseccontextprofiles.Where({$_._create_user -ne 'system' -And -not $_._system_owned -And $startDate[1] -le $_._create_time}).Count

	#Gathering group counts
	$group_count = $allsecgroups.Where({$_._create_user -ne 'system' -And -not $_._system_owned -And $startDate[1] -le $_._create_time}).Count

	$report_counts = @($policy_count,$rule_count,$svc_count,$cxt_pro_count,$group_count,$infra_category,$env_category,$app_category,$infra_rule_count,$env_rule_count,$app_rule_count,$eth_category,$emer_category,$eth_rule_count,$emer_rule_count)

	Write-Host "Report Summaries generated in $($stopwatch.Elapsed) (HH:MM:SS:MS)"
	return $report_counts
}

function Invoke-GeneratePolicyReport {

	Write-Host "Begin processing of Security Policies..."
	$stopwatch.Restart()

	# Loop through the data to create rows with conditional formatting
	$allsecpolicies.Where({
		$_._create_user -ne 'system' -And -not $_._system_owned -And $startDate[1] -le $_._create_time}).ForEach({
		
		$outerPolicy = $_		
	
		Write-Host "Processing Security Policy: $($_.display_name)"
		#$stopwatch.Restart()

		# Ensure that lines that contain the category and policy are a unique color compared to the rows that have rules
		
		$categoryColors = @{
			"Infrastructure" = "#2F8A4C"
			"Environment"    = "#4682B4"
			"Application"    = "#995CD5"
			"Ethernet"       = "#6F869E"
			"Emergency"      = "#C74C4C"
		}
		
		$rowStyle = ""
		if ($categoryColors.ContainsKey($_.category)) {
			$rowStyle = " style=`"background-color: $($categoryColors[$_.category]); `""
		}
		
		
			#logic to add applied to notation to applicable policy
			$policy_Applied_To = $null

			if ($_.scope -ne "ANY"){
				$policy_Applied_To = "<i>* 'Applied To' is configured for this Security Policy, and all rules within this policy inherit these settings</i>"
			}
		
			# Add the row to the HTML
			$html_policy += "    <tr$rowStyle>
				<td style='font-weight: bold;'>$($_.category)</td>
				<td>$($_.display_name)</td>
				<td colspan=7>$($policy_Applied_To)</td>
			</tr>`n"

			
		
		# Gathering all rules in the policy

			
			$sortrules = $_.children.Rule | Sort-Object -Property sequence_number		
	
			
			
			
			$rowCount = 0
			$sortrules.Where({$_.id }).ForEach({
				
				$rule = $_
				$ruleentryname = $_.display_name
				$ruleentryaction = $_.action
				#Each of the next five actions are taking the data from a field in the rule and then comparing it to security groups, services, or context
				#profiles to get the more human readable "display name". The "if" statements are there if and when the rule has an 'ANY', which won't 
				#match the existing query. Context Profiles are deliberately blank in this situation for readability. 
				#$ruleentrysrc = (($allsecgroups.Where({$_.path -in $rule.source_groups}).display_name -join "`n"))

				$rulesrcmatches = $rule.source_groups | Where-Object { $allsecgroupsLookup.ContainsKey($_) } | ForEach-Object { $allsecgroupsLookup[$_] }
				$ruleentrysrc = $rulesrcmatches -join "`n"

				if ($_.sources_excluded -eq "true"){
					$ruleentrysrc = "<s>$ruleentrysrc</s>"
				}
				if (-not $ruleentrysrc) {
					$ruleentrysrc = "Any"
				}

				#$ruleentrydst = (($allsecgroups.Where({$_.path -in $rule.destination_groups}).display_name -join "`n"))
				
				$ruledstmatches = $rule.destination_groups | Where-Object { $allsecgroupsLookup.ContainsKey($_) } | ForEach-Object { $allsecgroupsLookup[$_] }
				$ruleentrydst = $ruledstmatches -join "`n"
				
				if ($_.destinations_excluded -eq "true"){
					$ruleentrydst = "<s>$ruleentrydst</s>"
				}
				if (-not $ruleentrydst) {
					$ruleentrydst = "Any"
				}

				#$ruleentrysvc = (($allsecservices.Where({$_.path -in $rule.services}).display_name -join "`n"))
				$rulesvcmatches = $rule.services | Where-Object { $allsecservicesLookup.ContainsKey($_) } | ForEach-Object { $allsecservicesLookup[$_] }
				$ruleentrysvc = $rulesvcmatches -join "`n"
				if (-not $ruleentrysvc) {
					$ruleentrysvc = "Any"
				}

				#$ruleentrycxtpro = (($allseccontextprofiles.Where({$_.path -in $rule.profiles}).display_name -join "`n"))
				$rulecxtpromatches = $rule.profiles | Where-Object { $allseccontextprofilesLookup.ContainsKey($_) } | ForEach-Object { $allseccontextprofilesLookup[$_] }
				$ruleentrycxtpro = $rulecxtpromatches -join "`n"
				if (-not $ruleentrycxtpro) {
					$ruleentrycxtpro = ""
				}

				
				if ($outerPolicy.scope -ne "ANY"){
					$ruleentryappliedtomatches = $outerPolicy.scope | Where-Object { $allsecgroupsLookup.ContainsKey($_) } | ForEach-Object { $allsecgroupsLookup[$_] }
					#$ruleentryappliedto = $allsecgroups.Where({$_.path -in $outerPolicy.scope}).Foreach({ "$($_.display_name)*" }) -join "`n"
					$ruleentryappliedto = $ruleentryappliedtomatches -join "`n"
				} else {
					#$ruleentryappliedto = ($allsecgroups.Where({$_.path -in $rule.scope}).display_name) -join "`n"
					$ruleentryappliedtomatches = $rule.scope | Where-Object { $allsecgroupsLookup.ContainsKey($_) } | ForEach-Object { $allsecgroupsLookup[$_] }
					$ruleentryappliedto = $ruleentryappliedtomatches -join "`n"

					if (-not $ruleentryappliedto) {
						$ruleentryappliedto = "DFW"
					}
				}

				
					
				$rowCount++
							
				# Add the row to the HTML
				if ($rowCount % 2) {
					$rowStyle2 = ' style="background-color: #C4C4C4;"'
				} else { 
					$rowStyle2 = ' style="background-color: #AEB6BC;"'
				}

				# Adding logic to alter the colors of the first two columns depending on the policy category

		
				$categoryNullStyles = @{
					"Infrastructure" = ' style="background-color: #6BAC82; border-bottom: none; border-top: none;" colspan=2></td'
					"Environment"    = ' style="background-color: #6FA3D1; border-bottom: none; border-top: none;" colspan=2></td'
					"Application"    = ' style="background-color: #DBACFC; border-bottom: none; border-top: none;" colspan=2></td'
					"Ethernet"       = ' style="background-color: #98AFC4; border-bottom: none; border-top: none;" colspan=2></td'
					"Emergency"      = ' style="background-color: #E07A7A; border-bottom: none; border-top: none;" colspan=2></td'
				}
				
				$nullStyle = ""
				if ($categoryNullStyles.ContainsKey($outerPolicy.category)) {
					$nullStyle = $categoryNullStyles[$outerPolicy.category]
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
				
				
			})  
			#Write-Host "Security Policy: $($_.display_name) completed processing in $($stopwatch.Elapsed) (HH:MM:SS:MS)"
		})

		


		Write-Host "Completed Security Policies processing in $($stopwatch.Elapsed) (HH:MM:SS:MS)"
		return $html_policy
}

function Invoke-OutputReport {


	$dateLine = if ($startDate[1]) {

		@"
		<p>
        This report was generated using <u><b>Targeted Mode</b></u> with a start date of <u><b>$($startDate[0])</b></u>.
		Security Polices and associated objects created on or after this date will be included. 
    	</p>
"@
	} else {

		@"
		<p>
        This report was generated using <u><b>Complete Mode</b></u>. All Security Policies and associated objects are 
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
        <img src="data:image/png;base64,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
			ONai8rQ/LwAAAABJRU5ErkJggg==" alt="logo"  class="logo">
    </div>
	<p style="text-align:center;">
        <span style="font-size:22px;"><strong>Professional Services vDefend Segmentation Report</strong></span>
    </p>
	<p style="text-align:center;">
        <span style="font-size:18px;"><strong>Report Creation Date -  $($today)</strong></span>
    </p>
	<p style="text-align:center;">
        <span style="font-size:18px;"><strong>Targeted NSX Manager for Report Generation: $($nsxmgr)</strong></span>
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
				<strong>Report Capture Modes</strong> - Explains how the data was collected, whether as a 
				<em>complete snapshot of all user-created policies</em> or a 
				<em>targeted view of policies created after a specific date</em>. 
				The mode used for this report is noted in this section.
			</li>
			<li>
				<strong>Security Policy and Firewall Rule Summary</strong> - Highlights the total number of 
				<em>user-created security policies and firewall rules</em>, grouped by category. 
				It also includes a summary of <em>services, context profiles, and groups</em> that support these rules.
			</li>
			<li>
				<strong>Firewall Policy Overview</strong> - Provides a <em>snapshot of the firewall policy</em> at the time of reporting, 
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
			<li><strong>Complete Mode</strong> - Captures <em>all user-created security policies, firewall rules, and objects</em>, regardless of their creation time.</li>
			<li><strong>Targeted Mode</strong> - Captures <em>only user-created policies and objects that were created after a specified date</em>, providing a focused view of recent security changes.</li>
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
       If <strong>"Negate Selections"</strong> has been configured for sources or destinations in a firewall rule, the groups making up 
	   those sources or destinations will be marked with a strikethrough.
	   <br>
	   For example, a negated group in a firewall rule will appear as: <strong><s>Test Group</s></strong>
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

#prompt for nsx manager, username, and password
$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'
}

# Uri will get only securitypolices, groups, and context profiles under infra
# SvcUri will get only services under infra
# GlobalUri and GlobalSvcUri are only used when an LM has been identified as owned by a GM. This is for cases
# where local security policies/rules may be utilizing GM owned groups, services, and context profiles. 

$localOrGlobal = ""
$localManagedByGlobal = ""

# Prompt user to determine if the NSX Manager is Global
do {
    $localOrGlobal = Read-Host "Is the NSX Manager a Global NSX Manager? <Y/N>"
} until ($localOrGlobal -match "^[yYnN]$")  # Ensures only Y/y/N/n is accepted

if ($localOrGlobal -match "^[yY]$") {
    Write-Host "`n$nsxmgr will be queried as a Global NSX Manager.`n"
    $Uri = "https://$nsxmgr/global-manager/api/v1/global-infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;"
    $SvcUri = "https://$nsxmgr/global-manager/api/v1/global-infra?type_filter=Service;"
} else {
    # If Local, check if it is managed by a Global NSX Manager
    do {
        $localManagedByGlobal = Read-Host "Is the Local NSX Manager managed by a Global NSX Manager? <Y/N>"
    } until ($localManagedByGlobal -match "^[yYnN]$")  # Ensures only Y/y/N/n is accepted

    if ($localManagedByGlobal -match "^[yY]$") {
        Write-Host "`nGathering Local and Global objects from $nsxmgr.`n"
        $Uri = "https://$nsxmgr/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;"
        $SvcUri = "https://$nsxmgr/policy/api/v1/infra?type_filter=Service;"
        $globalUri = "https://$nsxmgr/policy/api/v1/global-infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;"
        $globalSvcUri = "https://$nsxmgr/policy/api/v1/global-infra?type_filter=Service;"



    } else {
        Write-Host "`n$nsxmgr will be queried as a Local NSX Manager.`n"
        $Uri = "https://$nsxmgr/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;"
        $SvcUri = "https://$nsxmgr/policy/api/v1/infra?type_filter=Service;"
    }
}



#Verify NSX credentials work before trying to fully gather data
Invoke-CheckNSXCredentials

#Gather the start date if one is required
$startDate = Get-StartDate

#Gathering all policies, groups, services, and context profiles
$allpolicies = Get-NSXDFW


#breaking out the gathered data byt Get-NSXDFW into discrete varables for later use
$allsecpolicies = $allpolicies.SecPolicies
$allsecgroups = $allpolicies.AllGroups
$allsecservices = $allpolicies.AllServices
$allseccontextprofiles = $allpolicies.AllContextProfiles

#Dictionary creations
#creating a dictionary lookup of allsecgroups.path to test speed difference for rule evaluations

$allsecgroupsLookup = @{}
$allsecgroups | ForEach-Object { $allsecgroupsLookup[$_.path] = $_.display_name }

#creating a dictionary lookup of allsecservices.path to test speed difference for rule evaluations

$allsecservicesLookup = @{}
$allsecservices | ForEach-Object { $allsecservicesLookup[$_.path] = $_.display_name }

#creating a dictionary lookup of allseccontextprofiles.path to test speed difference for rule evaluations

$allseccontextprofilesLookup = @{}
$allseccontextprofiles | ForEach-Object { $allseccontextprofilesLookup[$_.path] = $_.display_name }





#$header contains the formatting data for the the html file that will be created
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

#initializing $html_policy variable (although i should not need to do so) and then assiging it with the output of Invoke-GeneratePolicyReport
$html_policy = " "
$html_policy = Invoke-GeneratePolicyReport
#gathering the report count data
$report_counts = Invoke-GenerateBreakdownReport


#final function create the actual html output file utilizing the data gathered in prior steps
Invoke-OutputReport

$scriptTimer.Stop()

# Display total execution time
Write-Host "Total script execution time: $($scriptTimer.Elapsed) (HH:MM:SS:MS)"





