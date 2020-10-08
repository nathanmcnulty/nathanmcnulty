# MyStaff Password Reset Solution

This solution essentially treats Azure Administrative Units as a security group that can have roles such as password administrator applied to them. 

The setup process looks like this:

1. Create a list of groups whose members you would like to allow staff to reset passwords of

2. Create-MyStaffPrereqs.ps1 creates administrative units matching the names of groups in the list

3. Create-MyStaffPrereqs.ps1 creates security groups for password reset administrators with a prefix followed by the names of the groups in the list

4. Add password reset administrators to the new password reset administrator security groups

5. Update-MyStaffAUMembers.ps1 will get the membership of the groups whose names match the description of Administrative units and the existing members of the administrative units, and then it will add/remove users based on current group membership.

6. Update-MyStaffAUPWAdmins.ps1 will get the membership of the password administrator groups and the existing members of the password administrators role on the corresponding administrative units, and then it will add/remove users based on current group membership.