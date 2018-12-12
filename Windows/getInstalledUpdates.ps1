$Session = New-Object -ComObject "Microsoft.Update.Session"
$Searcher = $Session.CreateUpdateSearcher()

$historyCount = $Searcher.GetTotalHistoryCount()

$userName = [environment]::UserName
$desktopPath = [environment]::GetFolderPath("Desktop")
$filePath = "$desktopPath\installedUpdates.txt"
$ComputerName = $env:computername
$dateString = Get-Date -Format o #"yyyy-MM-dd HH:mm:ss"
$osBuild = [environment]::OSVersion.VersionString
$osVersion = (Get-WmiObject Win32_OperatingSystem).Caption
$osArchitecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture

Add-Content -Path "$filePath" -Value "Username:         $userName"
Add-Content -Path "$filePath" -Value "File location:    $filePath"
Add-Content -Path "$filePath" -Value "Computer name:    $ComputerName"
Add-Content -Path "$filePath" -Value "Timestamp:        $dateString"
Add-Content -Path "$filePath" -Value "OS Build:         $osBuild"
Add-Content -Path "$filePath" -Value "OS Version:       $osVersion ($osArchitecture)"
Add-Content -Path "$filePath" -Value ""

foreach($Update in $Searcher.QueryHistory(0, $historyCount)) {
    $UpdateDate = $Update.Date.ToString("yyyy-MM-dd HH:mm:ss")
    $UpdateOperation = switch($Update.Operation){
        1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}
    }

    $OutputObj = New-Object -TypeName PSobject
    $OutputObj | Add-Member -MemberType NoteProperty -Name UpdateTitle -Value $Update.Title
    $OutputObj | Add-Member -MemberType NoteProperty -Name Date -Value $UpdateDate
    $OutputObj | Add-Member -MemberType NoteProperty -Name Operation -Value $UpdateOperation

    Add-Content -Path "$filePath" -Value ($OutputObj | Format-List | Out-String).Trim()
    Add-Content -Path "$filePath" -Value ""
}
