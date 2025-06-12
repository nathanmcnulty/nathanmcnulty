# EOG prefix
$groupPrefix = "eog-department-"

# Helper function to create and maintain access packages
function ProcessAccessPackage {
	param (
		[string]$Name,
		[array]$GroupMembers
	)

	# If the access package doesn't exist, create it, otherwise get its Id
	if ($Name -notin $global:existingAccessPackages) {
		# Create access package
        $params = @{
			catalogId = $global:catalogId
			displayName = "$Name"
			description = "Resources for department group: $Name"
			isHidden = $true
			uniqueName = "$Name"
		}
		$accessPackageId = (Invoke-MgGraphRequest -Method POST -Uri "/beta/identityGovernance/entitlementManagement/accessPackages" -Body $params).Id

		# Create assignment policy for access package
		$params = @{
			accessPackageId = "$accessPackageId"
			displayName = "Automation"
			description = "Policy for automated assignments"
			accessReviewSettings = $null
			requestorSettings = @{
				scopeType = "NoSubjects"
				acceptRequests = $true
				allowedRequestors = @()
			}
			accessPackageNotificationSettings = @{
				isAssignmentNotificationDisabled = $true
			}
		}
		$assignmentPolicyId = (Invoke-MgGraphRequest -Method POST -Uri '/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies' -Body $params).Id
    } else {
        $accessPackageId = (Invoke-MgGraphRequest -Method GET -Uri "/beta/identityGovernance/entitlementManagement/accessPackages?`$filter=UniqueName eq '$Name'&`$select=Id").value.Id
		$assignmentPolicyId = (Invoke-MgGraphRequest -Method GET -Uri "/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies?`$filter=accesspackage/id eq '$accessPackageId'&`$select=id").value.Id
    }

	# Get existing assignments for the access package
	$existingAssignments = @()
	$uri = "/beta/identityGovernance/entitlementManagement/accessPackageAssignments?`$filter=accessPackageId eq '$accessPackageId'&`$select=targetId&`$top=999"
	do {
		$response = Invoke-MgGraphRequest -Method GET -Uri $uri
		$existingAssignments += $response.value.targetId
		$uri = $response.'@odata.nextLink'
	} while ($uri)

	# Compare existing assignments with current group members
	if ($existingAssignments -and $groupMembers) {
        $add = Compare-Object -ReferenceObject $groupMembers -DifferenceObject $existingAssignments -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
        $remove = Compare-Object -ReferenceObject $groupMembers -DifferenceObject $existingAssignments -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
    # If users have existing assignments but are no longer in the group, store the existing members in $remove
    } elseif ($existingAssignments) {
        # Consider adding logic to prevent large scale removal:
        # if ($existingAssignments.Count -gt 50) { Write-Warning "Group has more than 50 members, consider reviewing before removing all members" }
        $remove = $existingAssignments
    # If no existing assignments are found and users are in the group, add them to $add
    } else {
        $add = $groupMembers
    }

	# Add new users to access package assignments
    if ($add) { $add | ForEach-Object {
		$params = @{
			requestType = "adminAdd"
			assignment = @{
				targetId = "$_"
				assignmentPolicyId = "$assignmentPolicyId"
				accessPackageId = "$accessPackageId"
			}
		}
		# /v1.0/ is almost useless in Entitlement Management except for this endpoint which is apparently broken in /beta/...
		Invoke-MgGraphRequest -Method POST -Uri '/v1.0/identityGovernance/entitlementManagement/assignmentRequests' -Body $params
    }}

	# Remove users from group
    if ($remove) { $remove | ForEach-Object {
		$params = @{
			requestType = "adminRemove"
			assignment = @{
				targetId = "$_"
				assignmentPolicyId = "$assignmentPolicyId"
				accessPackageId = "$accessPackageId"
			}
		}
		# /v1.0/ is almost useless in Entitlement Management except for this endpoint which is apparently broken in /beta/...
		Invoke-MgGraphRequest -Method POST -Uri '/v1.0/identityGovernance/entitlementManagement/assignmentRequests' -Body $params
	}}
}

# Connect with scopes necessary to create catalogs, access packages, and maintain assignments
Connect-MgGraph -Scopes EntitlementManagement.ReadWrite.All,Group.Read.All -NoWelcome

# Get catalogId, create catalog if it doesn't exist
$global:catalogId = (Invoke-MgGraphRequest -Method GET -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs?`$filter=displayName eq 'Automated catalog'&`$select=id").value.id
if ($null -eq $catalogId) {
	$params = @{
		displayName = "Automated catalog"
		description = "Resources automated based on attributes"
		isExternallyVisible = $false
	}
	$global:catalogId = (Invoke-MgGraphRequest -Method POST -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs" -Body $params).Id
}

# Get all access packages in the catalog
$global:existingAccessPackages = (Invoke-MgGraphRequest -Method GET -Uri "/beta/identityGovernance/entitlementManagement/accessPackages?`$expand=accessPackageCatalog&`$filter=accessPackageCatalog/Id eq '$catalogId'&`$select=UniqueName,id").value.UniqueName

# Get all department groups and maintain access packages for each group
(Invoke-MgGraphRequest -Method GET -Uri "/beta/groups?`$filter=startswith(UniqueName,'$groupPrefix')&`$select=UniqueName").value | ForEach-Object {

	# Get members of the group
	$groupMembers = @()
    $uri = "/beta/groups/$($_.Id)/members?`$select=id&`$top=999"
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $groupMembers += $response.value.id
        $uri = $response.'@odata.nextLink'
    } while ($uri)
	
	# Process access package, create if necessary, and maintain assignments based on group membership
	ProcessAccessPackage -Name $_.UniqueName -GroupMembers $groupMembers
}

<# Delete all access packages from the catalog
Get-MgEntitlementManagementAccessPackage -Filter "catalog/id eq '$catalogId'" | ForEach-Object {
	Get-MgEntitlementManagementAssignment -AccessPackageId $_.Id | ForEach-Object {
		$params = @{
			requestType = "adminRemove"
			assignment = @{
				id = $_.Id
			}
		}
		New-MgEntitlementManagementAssignmentRequest -BodyParameter $params
	}
    Remove-MgEntitlementManagementAccessPackage -AccessPackageId $_.Id
}
#>