<#
# getInstalledUpdates.ps1
Retrieves all updates and writes them to a file "installedUpdates.txt" on the current user's Desktop

Usage:
./getInstalledUpdates.ps1
#>

# Windows Updates can be retrieved using the Microsoft.Update.Session COMObject
# Documentation: https://docs.microsoft.com/en-us/windows/desktop/api/wuapi/nn-wuapi-iupdatesession
$Session = New-Object -ComObject "Microsoft.Update.Session"

# Get reference for UpdateSearcher
$Searcher = $Session.CreateUpdateSearcher()

# Total number of objects present in UpdateHistory
$historyCount = $Searcher.GetTotalHistoryCount()

# First gather general information about the current computer and user
# Retrieve username from environment
$userName = [environment]::UserName
# Get current user's Desktop folderpath
$desktopPath = [environment]::GetFolderPath("Desktop")
# Output will be written to $filepath
$filePath = "$desktopPath\installedUpdates.txt"
# Get the current ComputerName
$ComputerName = $env:computername
# Get current timestamp in full ISO-8601 format (yyyy-MM-ddTHH:mm:ss.fffffffK)
$dateString = Get-Date -Format o
# Get the MS Windows Build version (e.g. "Microsoft Windows NT 6.1.7601 Service Pack 1" for Windows 7 SP1)
$osBuild = [environment]::OSVersion.VersionString
# Get the canonical Windows Version name (e.g. "Microsoft Windows 7 Enterprise" for Windows 7 SP1)
$osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
# Get the OS Architecture (32bit or 64bit)
$osArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

# Write the information to the output-file
Add-Content -Path "$filePath" -Value "Username:         $userName"
Add-Content -Path "$filePath" -Value "File location:    $filePath"
Add-Content -Path "$filePath" -Value "Computer name:    $ComputerName"
Add-Content -Path "$filePath" -Value "Timestamp:        $dateString"
Add-Content -Path "$filePath" -Value "OS Build:         $osBuild"
Add-Content -Path "$filePath" -Value "OS Version:       $osVersion ($osArchitecture)"
Add-Content -Path "$filePath" -Value ""

# Check if any updates are found
if ($historyCount -ne 0) {
    # Loop through all updates
    foreach($Update in $Searcher.QueryHistory(0, $historyCount)) {
        # Retrieve UpdateDate
        # Format is in yyyy-MM-dd HH:mm:ss because update-timestamp doesn't support milliseconds or timezone
        $UpdateDate = $Update.Date.ToString("yyyy-MM-dd HH:mm:ss")
        # Type of Update operation
        $UpdateOperation = switch($Update.Operation){
            1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}
        }

        # Create object to store Update information
        $OutputObj = New-Object -TypeName PSobject
        $OutputObj | Add-Member -MemberType NoteProperty -Name UpdateTitle -Value $Update.Title
        $OutputObj | Add-Member -MemberType NoteProperty -Name Date -Value $UpdateDate
        $OutputObj | Add-Member -MemberType NoteProperty -Name Operation -Value $UpdateOperation

        # Write update-information to output-file
        Add-Content -Path "$filePath" -Value ($OutputObj | Format-List | Out-String).Trim()
        # Add whiteline for readability
        Add-Content -Path "$filePath" -Value ""
    }
} else {
    # If no updates are found, write string to output-file
    Add-Content -Path "$filePath" -Value "No updates found"
}
