<#
Usage:
./getInstalledSoftware.ps1 [ComputerName=<Current computer>]

Arguments           Description                         Default value
-ComputerName=      Specify ComputerName (optional)     Current computername
#>

# Set up parameters for script
[cmdletbinding()]
param(
    [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ComputerName = $env:computername
)

# Store location of UnInstall registry keys (32bit and 64bit)
# This is the best place to get a list of installed software in Windows
begin {
    $UninstallRegKeys=@("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
}

# Start of script
process {
    # First gather general information about the current computer and user

    # Retrieve username from environment
    $userName = [environment]::UserName
    # Get current user's Desktop folderpath
    $desktopPath = [environment]::GetFolderPath("Desktop")
    # Output will be written to $filepath
    $filePath = "$desktopPath\installedSoftware.txt"
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

    # Loop through the list of provided ComputerName(s)
    foreach($Computer in $ComputerName) {
        Write-Verbose "Working on $Computer"

        if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {
            # Loop through the 32bit & 64bit UninstallRegistryKeys
            foreach($UninstallRegKey in $UninstallRegKeys) {
                # Check if UninstallKey is present and readable
                try {
                    $HKLM = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$computer)
                    $UninstallRef = $HKLM.OpenSubKey($UninstallRegKey)
                    # List of all applications listed in UninstallRegKey
                    $Applications = $UninstallRef.GetSubKeyNames()
                } catch {
                    Write-Verbose "Failed to read $UninstallRegKey"
                    Continue
                }

                # Loop through installed applications
                foreach ($App in $Applications) {
                    $AppRegistryKey = $UninstallRegKey + "\\" + $App
                    $AppDetails = $HKLM.OpenSubKey($AppRegistryKey)

                    # AppGUID is Windows' internal reference to applications & services
                    $AppGUID = $App
                    # Name of the application
                    $AppDisplayName = $($AppDetails.GetValue("DisplayName"))
                    # Version of the application (if known)
                    $AppVersion = $($AppDetails.GetValue("DisplayVersion"))
                    # Vendor of application
                    $AppPublisher = $($AppDetails.GetValue("Publisher"))
                    # Install date of application (if known)
                    $AppInstalledDate = $($AppDetails.GetValue("InstallDate"))
                    # Uninstall key for application (method how to uninstall)
                    $AppUninstall = $($AppDetails.GetValue("UninstallString"))

                    # Get application target architecture (x86 for 32bit, x64 for 64bit)
                    if($UninstallRegKey -match "Wow6432Node") {
                        $Softwarearchitecture = "x86"
                    } else {
                        $Softwarearchitecture = "x64"
                    }

                    # Internal Windows tools can have no display name, genuine applications always have a displayname
                    if(!$AppDisplayName) {
                        Continue
                    }

                    # Create an object to store Application (un)install information
                    $OutputObj = New-Object -TypeName PSobject
                    $OutputObj | Add-Member -MemberType NoteProperty -Name AppName -Value $AppDisplayName
                    $OutputObj | Add-Member -MemberType NoteProperty -Name AppVersion -Value $AppVersion
                    $OutputObj | Add-Member -MemberType NoteProperty -Name AppVendor -Value $AppPublisher
                    $OutputObj | Add-Member -MemberType NoteProperty -Name InstalledDate -Value $AppInstalledDate
                    $OutputObj | Add-Member -MemberType NoteProperty -Name UninstallKey -Value $AppUninstall
                    $OutputObj | Add-Member -MemberType NoteProperty -Name AppGUID -Value $AppGUID
                    $OutputObj | Add-Member -MemberType NoteProperty -Name SoftwareArchitecture -Value $Softwarearchitecture

                    # Write applicaton information to output-file
                    Add-Content -Path "$filePath" -Value ($OutputObj | Format-List | Out-String).Trim()

                    # Add whiteline for readability
                    Add-Content -Path "$filePath" -Value ""
                }
            }
        }
    }
}

end {}
