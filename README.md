# Export-EventLogs
A PowerShell script to export Windows event logs as EVTX, TXT, and CSV file formats.

## Usage
Running the script without any parameters will provide a list of all event logs on the system where you can select the list you wish to export.
![Screenshot of GridView showing list of event logs, user can select multiple entries to export](/_SupportFiles/OGV_SelectEvents.png "Select events GridView")

You can also provide list of event logs to export as follows,
```PowerShell
.\Export-EventLogs.ps1 -EventLogNames "Microsoft-Windows-AAD/Operational","Microsoft-Windows-VHDMP-Operational"
```

The results are saved in a folder named .\EventLogs