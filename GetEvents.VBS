'************************************************
'GetEvents7.VBS
'Version 7.1.22
'Date: 05-20-2013
'Author: Andre Teixeira - andret@microsoft.com
'************************************************
Option Explicit

Const strCOMPUTER = "."
Const ForReading = 1, ForWriting = 2, ForAppending = 8
Const DEFAULTPREFIXFORFILENAMES = "%COMPUTERNAME%_evt_"
Const OpenFileMode = -2 '"Auto"

Dim bShowCtrlChars
Dim bShowQuotesinCSV
Dim bCSVOutput
Dim bTXTOutput
Dim bEVTXOutput
Dim bEVTOutput
Dim bWEVTXMLOutput
Dim bWEVTTXTOutput
Dim bETLOutput
Dim bGenerateAllWMIEvents
Dim bGenerateAllEvents
Dim bNoTableFormatinTXT
Dim bNoHeaderinTXT
Dim bNoScriptStats
Dim bArgumentsContainOutput
Dim arrEventLogNames()
Dim strEVTXFileName
Dim strWEVTXMLFileName
Dim strWEVTTXTFileName
Dim bFilterbyDays
Dim intNumberofDaystoFilter
Dim strOutputFolder
Dim bKeepEmptyFiles
Dim strBuffer, bolDisplayMsg
Dim bUseWevtutil
Dim bEvtxExtended
Dim bIncludeSIDCol
Dim bIncludeTimeGeneratedCol
Dim bIncludeUserCol
Dim bIncludeComputerCol
Dim bIncludeSourceCol
Dim bIncludeTaskCol
Dim bFilterQuery
Dim strFilterQuery
Dim bXMLFormatRendered
Dim bLogExclusionEnabled
Dim arrLogExceptionList
Dim bOSSupportChannels
Dim objSWbemDateTime
Dim intCurrentOSBuild
Dim bPostArchiveMainEventLogs
Dim bForceMTAFiles
Dim strPrefixforFilenames
Dim strSuffixforFilenames

Dim strTimeZoneName
Dim intCurrentTzBias
Dim intCurrentBiasfromWMIDateTime

Dim bArgumentFileEnabled
Dim strArgumentFileFilePath

Dim objWMIService
Dim objTXTFile
Dim objCSVFile
Dim objWevtutilTXTFile
Dim objExec
Dim objShell
Dim objFSO

Dim bGenerateSDP2Alert
Dim bGenerateScriptedDiagXMLAlerts
Dim arrScriptedDiagXML
Dim arrAlertEventIDtoMonitor
Dim arrAlertEventSourcetoMonitor
Dim arrAlertEventLogtoMonitor
Dim arrAlertEventDaysToMonitor
Dim arrAlertEventMoreInformation
Dim arrAlertSection
Dim arrAlertSectionPriority
Dim strAlertSkipRootCauseDetection

Dim arrAlertEventCount
Dim arrAlertEventType
Dim arrAlertEventLastOcurrenceDate
Dim arrAlertEventComputername
Dim arrAlertFirstOcurrenceDate
Dim arrAlertEventLastOcurrenceMessage
Dim arrAlertSkipRootCauseDetection
Dim bEventLogIncludesAlert

Const ALERT_INFORMATION = 1
Const ALERT_WARNING = 2
Const ALERT_ERROR = 3
Const ALERT_CRITICAL = 4
Const ALERT_NOTE = 5

Main()

Sub Main()
    Dim strValidateArguments
    
    strBuffer = ""
    bolDisplayMsg = False
    
    lineOut "GetEvents7.VBS"
    lineOut "Revision 7.1.22"
    lineOut "2006-2013 Microsoft Corporation"
    
    If DetectScriptEngine Then
        bolDisplayMsg = True
        lineOut ""
                                    
        Set objShell = CreateObject("WScript.Shell")
        Set objFSO = CreateObject("Scripting.FileSystemObject")

        intCurrentOSBuild = GetCurrentOSBuild
        bOSSupportChannels = OSSupportChannels
        strValidateArguments = ValidateArguments
        
        If (strValidateArguments = "0" Or bArgumentFileEnabled) Then
            If strValidateArguments = "0" Then
                wscript.Echo "Command line arguments:"
                wscript.Echo "-----------------------"
                DisplayArguments
            End If
            If bArgumentFileEnabled Then
                Dim arrArgumentFile, bError, strError
                If ProcessArgumentFile(arrArgumentFile) Then
                    wscript.Echo ""
                    ProcessArgumentList arrArgumentFile, bError, strError
                    If bError Then
                        wscript.Echo "-- Error processing argument file:"
                        wscript.Echo strError
                        wscript.Echo ""
                    End If
                    If bArgumentsContainOutput Then
                        wscript.Echo "User/Command line merged arguments:"
                        wscript.Echo "-----------------------------------"
                        wscript.Echo ""
                        DisplayArguments
                    End If
                End If
            End If
            If bArgumentsContainOutput Then
                doWork
            Else
                ShowArgumentsSyntax ("")
            End If
        Else
            ShowArgumentsSyntax (strValidateArguments)
        End If
    End If
    lineOut ""
    bolDisplayMsg = True
    If Not IsEmpty(objExec) Then
        While objExec.Status = 0
            wscript.Sleep 200
        Wend
    End If
    lineOut "****** Script Finished ******"
End Sub

Sub DisplayArguments()
   
    Dim strProductName, x
    'On Error Resume Next
    
    strProductName = objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")
   
    If bGenerateAllWMIEvents Then
        wscript.Echo "Event log name  : All WMI event logs"
    ElseIf bGenerateAllEvents Then
        wscript.Echo "Event log name  : All event logs"
    Else
        If UBound(arrEventLogNames) = 0 Then
            wscript.Echo "Event log name  : " & arrEventLogNames(0) & ""
        Else
            wscript.Echo "Event log names : " & arrEventLogNames(0)
            For x = 1 To UBound(arrEventLogNames)
                wscript.Echo "                  " & arrEventLogNames(x)
            Next
        End If
    End If
    
    If bUseWevtutil And bOSSupportChannels Then
        wscript.Echo "Export method   : WevtUtil"
    Else
        wscript.Echo "Export method   : WMI" & IIf(bUseWevtutil, "/Wevtutil", "")
    End If
    
    If strPrefixforFilenames <> DEFAULTPREFIXFORFILENAMES Then
        wscript.Echo ""
        wscript.Echo "Output prefix: " & strPrefixforFilenames
    End If
    
    If Len(strSuffixforFilenames) <> 0 Then
        If strPrefixforFilenames = DEFAULTPREFIXFORFILENAMES Then wscript.Echo ""
        wscript.Echo "Output suffix: " & strSuffixforFilenames
    End If
    
    wscript.Echo ""
    wscript.Echo "Export operation:"
    
    If bCSVOutput Then
        wscript.Echo "   CSV output - Enabled"
    End If
    
    If bTXTOutput Then
        wscript.Echo "   TXT output - Enabled"
    End If
        
    If bWEVTXMLOutput And bOSSupportChannels Then
        wscript.Echo "   XML output - Enabled"
    ElseIf bWEVTXMLOutput Then
        wscript.Echo "   XML output - Not supported in " + strProductName
    End If
        
    If bETLOutput And bOSSupportChannels Then
        wscript.Echo "   ETL output - Enabled"
    ElseIf bETLOutput Then
        wscript.Echo "   ETL output - Not supported in " + strProductName
    End If
        
    If bWEVTTXTOutput And bOSSupportChannels Then
        wscript.Echo "   TXT/Wevtutil output - Enabled"
    ElseIf bWEVTTXTOutput Then
        wscript.Echo "   TXT/Wevtutil output - Not supported in " + strProductName
    End If
        
    If bEVTOutput And (Not bOSSupportChannels) Then
        wscript.Echo "   EVT Backup - Enabled"
    ElseIf bEVTOutput Then
        wscript.Echo "   EVT backup - Not supported in " + strProductName
        bEVTOutput = False
    End If
        
    If bEVTXOutput And bOSSupportChannels Then
        If bEvtxExtended Then
            wscript.Echo "   EVTX output with Extended messages - Enabled"
            If bForceMTAFiles And bGenerateAllEvents Then
                wscript.Echo "   Archive operation will be forced."
            End If
        Else
            wscript.Echo "   EVTX output - Enabled"
        End If
    ElseIf bEVTXOutput Then
        wscript.Echo "   EVTX output - Not supported in " + strProductName
        bEVTXOutput = False
    End If
        
    If Len(strOutputFolder) > 0 Then
        wscript.Echo "   Output folder - '" & strOutputFolder & "'"
    End If
    
    If (Not (bShowQuotesinCSV)) Or bShowCtrlChars Or bNoTableFormatinTXT Or bLogExclusionEnabled Or _
        bFilterbyDays Or bNoHeaderinTXT Or bNoScriptStats Or bKeepEmptyFiles _
        Or bIncludeSIDCol Or bPostArchiveMainEventLogs Or (Not bIncludeUserCol) Or bIncludeTimeGeneratedCol _
        Or bFilterQuery Or (Not bIncludeTaskCol) Or (Not bIncludeSourceCol) _
        Or (Not (bEvtxExtended)) Or (bXMLFormatRendered) Or (bGenerateSDP2Alert) Or (bGenerateScriptedDiagXMLAlerts) _
        Then
        
        wscript.Echo ""
        wscript.Echo "Options:"
        
        If bLogExclusionEnabled Then
            wscript.Echo "   Exclude following event logs:"
            For x = 0 To UBound(arrLogExceptionList)
                wscript.Echo "          " & arrLogExceptionList(x)
            Next
            wscript.Echo ""
        End If
        
        If bShowCtrlChars Then
            wscript.Echo "   Display control chars translation in event description"
        End If
        
        If bNoHeaderinTXT Then
            wscript.Echo "   Do not display control chars translation header in txt output"
        End If
        
        If bNoScriptStats Then
            wscript.Echo "   Do not display script statistics in output"
        End If
        
        If Not bShowQuotesinCSV Then
            wscript.Echo "   Do not show double quotes in CSV output"
        End If
        
        If bNoTableFormatinTXT Then
            wscript.Echo "   TXT output in plain text format"
        End If
                
        If bKeepEmptyFiles Then
            wscript.Echo "   Keep files with 0 records"
        End If
        
        If bOSSupportChannels Then
        
            If bXMLFormatRendered Then
                wscript.Echo "   XML output will be in RenderedXml format"
            End If
            
            If Not bEvtxExtended Then
                wscript.Echo "   EVTX output will not contain extended MTA files"
            End If
        
            If bIncludeSIDCol Then
                wscript.Echo "   Include a column with SID information"
            End If
                   
            If bIncludeTimeGeneratedCol Then
                wscript.Echo "   Include Time Generated column"
            End If
            
            If Not bIncludeUserCol Then
                wscript.Echo "   Do not include Username column in report"
            End If
            
            If Not bIncludeSourceCol Then
                wscript.Echo "   Do not include Source column in report"
            End If
        
            If Not bIncludeTaskCol Then
                wscript.Echo "   Do not include Task Category column in report"
            End If
            
            If bPostArchiveMainEventLogs Then
                wscript.Echo "   Archive only the WMI/compatible event logs"
            End If
            
        End If
    
        If bFilterQuery Then
            wscript.Echo ""
            wscript.Echo "   Filtering query:"
            wscript.Echo "   {" & strFilterQuery & "}"
        End If
    
        If bFilterbyDays Then
            Dim strStartDate, strEndDate, strStartTime, strStartDateDisplay, strStartTimeDisplay
            strStartDate = DateAdd("n", (intNumberofDaystoFilter * -60), Now)
            strStartDateDisplay = Month(strStartDate) & "\" & Day(strStartDate) & "\" & Year(strStartDate)
            strStartTimeDisplay = TimeValue(strStartDate)
            wscript.Echo "   Events filtered from '" & strStartDateDisplay & " " & strStartTimeDisplay & "'"
        End If
        
        If bGenerateSDP2Alert Or bGenerateScriptedDiagXMLAlerts Then
            wscript.Echo ""
            If bGenerateScriptedDiagXMLAlerts Then
                    wscript.Echo "   Generate Scripted Diagnostic XML for the following rules:"
                Else
                    wscript.Echo "   Generate SDP 2.x PLA Alerts for the following rules:"
            End If
            wscript.Echo ""
            For x = 0 To UBound(arrAlertEventLogtoMonitor)
                wscript.Echo "      Event Log       : " & arrAlertEventLogtoMonitor(x)
                wscript.Echo "      Days            : " & CStr(arrAlertEventDaysToMonitor(x))
                wscript.Echo "      Event Source    : " & arrAlertEventSourcetoMonitor(x)
                wscript.Echo "      Event ID        : " & arrAlertEventIDtoMonitor(x)
                If IsNumeric(arrAlertEventMoreInformation(x)) <> 0 Then
                    wscript.Echo "      Related article : KB " & arrAlertEventMoreInformation(x)
                End If
                wscript.Echo ""
            Next
        End If
    End If
End Sub

Sub OpenWMIService()
    On Error Resume Next
    Err.Clear
    If IsEmpty(objWMIService) Then
        wscript.Echo ("   Opening WMI Service")
        Set objWMIService = GetObject("winmgmts:" & _
        "{impersonationLevel=impersonate, (Backup, Security)}!\\" & _
        ".\root\cimv2")
                
        If Err.Number <> 0 Then
           wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": binding to WMI Service"
           wscript.Echo Err.Source & " - " & Err.Description
           wscript.Quit
        End If
    End If
End Sub

Function ProcessArgumentFile(ByRef arrUserArgumentList)
    'Arguments in user file should be separated by a ';'
    On Error Resume Next
    Err.Clear
    
    Dim objArgumentFileFile
    
    wscript.Echo "Using argument file : '" & UCase(objFSO.GetFileName(strArgumentFileFilePath)) & "'"
    
    If objFSO.FileExists(strArgumentFileFilePath) Then
        Set objArgumentFileFile = objFSO.OpenTextFile(strArgumentFileFilePath, ForReading, False, OpenFileMode)
        
        If Err.Number = 0 Then
            While Not objArgumentFileFile.AtEndOfStream
                If IsEmpty(arrUserArgumentList) Then
                    arrUserArgumentList = StringToArray(objArgumentFileFile.ReadLine, ";")
                Else
                    arrUserArgumentList = AddtoArray(arrUserArgumentList, StringToArray(objArgumentFileFile.ReadLine, ";"))
                End If
                ProcessArgumentFile = True
            Wend
        Else
            ProcessArgumentFile = False
        End If
        objArgumentFileFile.Close
    
        If Err.Number <> 0 Then
            DisplayError "Processing Argument File", Err.Number, "ProcessArgumentFile", Err.Description
        End If
    Else
        DisplayError "Processing Argument File", 2, "ProcessArgumentFile", "The file " & strArgumentFileFilePath & " does not exist. Argument file will be ignored."
    End If
End Function

Function AddtoArray(arrSourceArray, arrObjectToAdd)
    On Error Resume Next
    Dim y, varFirstMember, bWasSourceArrayNothing
    
    If IsEmpty(arrSourceArray) Then
        If Not IsArray(arrObjectToAdd) Then
            ReDim arrSourceArray(0)
            arrSourceArray(0) = arrObjectToAdd
        Else
            arrSourceArray = arrObjectToAdd
        End If
    Else
        If Not IsArray(arrSourceArray) Then
            If TypeName(arrSourceArray) = "Nothing" Then
                ReDim arrSourceArray(0)
                bWasSourceArrayNothing = True
            Else
                varFirstMember = arrSourceArray
                ReDim arrSourceArray(0)
                arrSourceArray(0) = varFirstMember
                bWasSourceArrayNothing = False
            End If
        Else
            bWasSourceArrayNothing = False
        End If
        If Not IsEmpty(arrObjectToAdd) Then
            If IsArray(arrObjectToAdd) Then
                For y = 0 To UBound(arrObjectToAdd)
                    If bWasSourceArrayNothing Then
                        ReDim Preserve arrSourceArray(UBound(arrSourceArray))
                        arrSourceArray(UBound(arrSourceArray) - 1) = arrObjectToAdd(y)
                    Else
                        ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                        arrSourceArray(UBound(arrSourceArray)) = arrObjectToAdd(y)
                    End If
                Next
            Else
                If bWasSourceArrayNothing Then
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray))
                    arrSourceArray(UBound(arrSourceArray)) = arrObjectToAdd
                Else
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                    arrSourceArray(UBound(arrSourceArray)) = arrObjectToAdd
                End If
            End If
        End If
    End If
    AddtoArray = arrSourceArray
End Function

Sub doWork()
    Dim bGenerateOutput, x, y
    wscript.Echo ""
    wscript.Echo "Exporting Event Logs..."
    Dim TimeStart
    Dim strEventLogName, arrEventLogsToExport

    On Error Resume Next

    TimeStart = Now
    intCurrentTzBias = ObtainTimeZoneBias
    intCurrentBiasfromWMIDateTime = -1
    
    strPrefixforFilenames = ReplaceEnvVars(strPrefixforFilenames)
    strSuffixforFilenames = ReplaceEnvVars(strSuffixforFilenames)
    
    If bGenerateAllWMIEvents Then
        Dim objEvents, objEventLog
        OpenWMIService
        Set objEvents = objWMIService.ExecQuery("Select * from Win32_NTEventLogFile", , 48)
        
        If Err.Number <> 0 Then
            DisplayError "Opening Win32_NTEventLogFile object.", Err.Number, "DoWork", Err.Description
            wscript.Quit
        End If
        
        For Each objEventLog In objEvents
            If bLogExclusionEnabled Then
                For x = 0 To UBound(arrLogExceptionList)
                    If LCase(arrLogExceptionList(x)) = LCase(objEventLog.LogFileName) Then
                        wscript.Echo "   Skipping Event Log: '" & objEventLog.LogFileName & "'"
                    Else
                        AddtoArray arrEventLogsToExport, objEventLog.LogFileName
                    End If
                Next
            Else
                AddtoArray arrEventLogsToExport, objEventLog.LogFileName
            End If
        Next
        
        If bEVTOutput Then
            wscript.Echo "   Event Log Backup: "
            For Each strEventLogName In arrEventLogsToExport
                'Backup all event logs first to EVT, then generate other formats
                wscript.Echo "      Event Log: " & strEventLogName & ""
                BackupEventLog (strEventLogName)
            Next
            wscript.Echo ""
        End If
        
        For Each strEventLogName In arrEventLogsToExport
            wscript.Echo "   Converting Event Log: '" & strEventLogName & "'"
            GenerateOutput (strEventLogName)
        Next
        
    ElseIf bGenerateAllEvents Then
    
        If ((bEVTXOutput And bEvtxExtended) And ((intCurrentOSBuild = 6000) Or ((intCurrentOSBuild = 6001) And (IsSP1Beta)))) And (Not bForceMTAFiles) Then
            wscript.Echo "      You have used /allevents and /evtx argument in Vista/ Server 2008 pre SP1."
            wscript.Echo "      In order to avoid problems in Event Logs Service,"
            wscript.Echo "      the archive operation will not be generated for all events."
            wscript.Echo "      Only the main event logs will have the MTA files."
            wscript.Echo ""
            bEvtxExtended = False
            bPostArchiveMainEventLogs = True
        End If
    
        Dim arrLines()
        ReDim arrLines(0)
        If ShellExec("%COMSPEC% /c %WINDIR%\System32\wevtutil.exe el", "", True, False, False) = 0 Then
        
            Do While Not objExec.StdOut.AtEndOfStream
                ReDim Preserve arrLines(UBound(arrLines) + 1)
                arrLines(UBound(arrLines)) = objExec.StdOut.ReadLine()
            Loop
            objExec.StdOut.Close

            For y = 1 To UBound(arrLines)
                strEventLogName = arrLines(y)
                bGenerateOutput = True
                If bLogExclusionEnabled Then
                    For x = 0 To UBound(arrLogExceptionList)
                        If LCase(arrLogExceptionList(x)) = LCase(strEventLogName) Then
                            bGenerateOutput = False
                        End If
                    Next
                End If
                If bGenerateOutput Then
                    wscript.Echo "   Event Log: '" & strEventLogName & "'"
                    GenerateOutput (strEventLogName)
                Else
                    wscript.Echo "   Skipping: '" & strEventLogName & "'"
                End If
            Next
        
        End If
        If bPostArchiveMainEventLogs Then
            PostArchiveMainEventLogs
        End If
    Else
        If bEVTOutput Then
            For Each strEventLogName In arrEventLogNames
                bGenerateOutput = True
                If bLogExclusionEnabled Then
                    For x = 0 To UBound(arrLogExceptionList)
                        If LCase(arrLogExceptionList(x)) = LCase(strEventLogName) Then
                            bGenerateOutput = False
                            Exit For
                        End If
                    Next
                End If
                If bGenerateOutput Then
                    wscript.Echo "   Event Log Backup: '" & strEventLogName & "'"
                    BackupEventLog (strEventLogName)
                Else
                    wscript.Echo "   Skipping: '" & strEventLogName & "'"
                End If
            Next
        End If
        For Each strEventLogName In arrEventLogNames
            bGenerateOutput = True
            If bLogExclusionEnabled Then
                For x = 0 To UBound(arrLogExceptionList)
                    If LCase(arrLogExceptionList(x)) = LCase(strEventLogName) Then
                        bGenerateOutput = False
                        Exit For
                    End If
                Next
            End If
            If bGenerateOutput Then
                wscript.Echo "   Exporting Event Log: '" & strEventLogName & "'"
                GenerateOutput (strEventLogName)
            Else
                wscript.Echo "   Skipping: '" & strEventLogName & "'"
            End If
        Next
    End If
    
    If (bGenerateSDP2Alert Or bGenerateScriptedDiagXMLAlerts) Then
        If bEventLogIncludesAlert Then
            WriteAlertsToXMLFiles
        Else
            wscript.Echo "   There are no alerts for any event log processed."
        End If
    End If
    
    wscript.Echo ""
    wscript.Echo "Script completed in " & CStr(FormatNumber(DateDiff("s", TimeStart, Now), 0)) & " seconds."
    
End Sub

Sub WriteAlertsToXMLFiles()
    On Error Resume Next
    Dim x, strAlertMessage, strMoreInformation, intAlertType
    
    If IsArray(arrAlertEventLogtoMonitor) Then
        If Not IsEmpty(arrAlertEventLogtoMonitor) Then
            wscript.Echo ""
            If bGenerateSDP2Alert Then
                wscript.Echo "Writing MSDT PLA Alerts:"
            Else
                wscript.Echo "Writing Scripted Diagnostic Alerts:"
            End If
            For x = 0 To UBound(arrAlertEventLogtoMonitor)
                If arrAlertEventCount(x) > 0 Then
                    Select Case arrAlertEventType(x)
                        Case 4
                            intAlertType = ALERT_CRITICAL
                        Case 3
                            intAlertType = ALERT_INFORMATION
                        Case 2
                            intAlertType = ALERT_WARNING
                        Case 1
                            intAlertType = ALERT_ERROR
                        Case Else
                            intAlertType = ALERT_NOTE
                    End Select
                    
                    Dim objPLA
                    Set objPLA = New ezPLA
                    
                    wscript.Echo "    Event ID " & CStr(arrAlertEventIDtoMonitor(x)) & " from " & arrAlertEventSourcetoMonitor(x) & " on " & arrAlertEventLogtoMonitor(x) & " log."
                    
                    'Generate Alert Message:
    
                    If arrAlertEventCount(x) = 1 Then
                        strAlertMessage = "There is one event <b>" & CStr(arrAlertEventIDtoMonitor(x)) & "</b> from <b>" & arrAlertEventSourcetoMonitor(x) & "</b> on " & arrAlertEventLogtoMonitor(x) & " event log from " & GetAgeDescription(arrAlertFirstOcurrenceDate(x)) & " ago: <p/>"
                    Else
                        strAlertMessage = "There are <b>" & CStr(arrAlertEventCount(x)) & "</b> events <b>" & CStr(arrAlertEventIDtoMonitor(x)) & "</b> from <b>" & arrAlertEventSourcetoMonitor(x) & "</b> on " & arrAlertEventLogtoMonitor(x) & " event log in " & GetAgeDescription(arrAlertFirstOcurrenceDate(x)) & ".<p/>" & _
                                          "The most recent occurrence for this event is from " & GetAgeDescription(arrAlertEventLastOcurrenceDate(x)) & " ago: <p/>"
                    End If
                    strAlertMessage = strAlertMessage & _
                                        "<table><tr><td>Date: </td><td>" & CStr(arrAlertEventLastOcurrenceDate(x)) & "</td></tr>" & _
                                        "<tr><td>Computer name: </td><td>" & CStr(arrAlertEventComputername(x)) & "</td></tr>" & _
                                        "<tr><td>Source: </td><td>" & CStr(arrAlertEventSourcetoMonitor(x)) & "</td></tr>" & _
                                        "<tr><td>ID: </td><td>" & CStr(arrAlertEventIDtoMonitor(x)) & "</td></tr>" & _
                                        "<tr><td valign='top'>Description:</td><td valign='top'>" & arrAlertEventLastOcurrenceMessage(x) & "</td></tr></table>"
                                                        
                    If Len(arrAlertEventMoreInformation(x)) > 0 Then
                        strMoreInformation = "For more information, please consult the following article: "
                        If IsNumeric(arrAlertEventMoreInformation(x)) > 0 Then
                            strMoreInformation = strMoreInformation & "<a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;" & CStr(arrAlertEventMoreInformation(x)) & "'>KB " & CStr(arrAlertEventMoreInformation(x)) & "</a>"
                        ElseIf LCase(Left(arrAlertEventMoreInformation(x), 4)) = "http" Then
                            strMoreInformation = strMoreInformation & "<a target='_blank' href='" & CStr(arrAlertEventMoreInformation(x)) & "'>" & arrAlertEventMoreInformation(x) & "</a>"
                        Else
                            strMoreInformation = arrAlertEventMoreInformation(x)
                        End If
                    Else
                        strMoreInformation = ""
                    End If
                    
                    If bGenerateSDP2Alert Then
                        objPLA.Section = arrAlertSection(x)
                        objPLA.SectionPriority = arrAlertSectionPriority(x)
                        
                        objPLA.AlertType = intAlertType
                        objPLA.AlertPriority = CInt(30 / intAlertType)
                        objPLA.Symptom = "Event Log Message"
                        objPLA.Details = strAlertMessage
                        objPLA.MoreInformation = strMoreInformation
                        objPLA.AddAlerttoPLA
                    ElseIf (bGenerateScriptedDiagXMLAlerts) Then
                        AddScriptedDiagAlert intAlertType, arrAlertSection(x), strAlertMessage, strMoreInformation, CInt(30 / intAlertType), arrAlertSkipRootCauseDetection(x), arrAlertEventLogtoMonitor(x), arrAlertEventIDtoMonitor(x), arrAlertEventSourcetoMonitor(x), arrAlertEventCount(x), arrAlertFirstOcurrenceDate(x), arrAlertEventLastOcurrenceDate(x), arrAlertEventLastOcurrenceMessage(x), arrAlertEventDaysToMonitor(x)
                    End If
                Else
                    wscript.Echo "    No ocurrences for Event ID " & CStr(arrAlertEventIDtoMonitor(x)) & " from " & arrAlertEventSourcetoMonitor(x) & " on " & arrAlertEventLogtoMonitor(x) & " log."
                End If
            Next
            If (bGenerateScriptedDiagXMLAlerts) And (Not IsEmpty(arrScriptedDiagXML)) Then
                WriteAlertsToScriptedDiagXML
            End If
        End If
    End If
End Sub

Function ConvertDateToString(dteDate)  
    rem dteDate = dateAdd("n", intCurrentTzBias, dteDate)
    Dim hr, ampm
    hr = Hour(dteDate)
    If hr >= 12 Then
      If hr <> 12 Then
          hr = CStr(hr - 12)
      End If
      ampm = "PM"
    Else
      ampm = "AM"
      If hr = 0 Then hr = "12"
    End If
    ConvertDateToString = cstr(Year(dteDate)) & "-" & Right("0" & cstr(Month(dteDate)), 2) & "-" & Right("0" & cstr(Day(dteDate)), 2) & " " & Right("0" & hr, 2) & ":" & Right("0" & cstr(Minute(dteDate)),2) & ":" & Right("0" & cstr(Second(dteDate)),2) & ampm
End Function 

Sub AddScriptedDiagAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority, bSkipRootCauseDetection, strEventLog, strEventId, strEventSource, strAlertEventCount, strAlertFirstOcurrenceDate, strAlertEventLastOcurrenceDate, strAlertEventLastOcurrenceMessage, intAlertEventDaysToMonitor)
    
    Dim strAlertType, strAlertXML
    Dim bWriteScriptedDiagAlert
    If bGenerateScriptedDiagXMLAlerts Then
        
        Select Case intAlertType
            Case ALERT_INFORMATION
                strAlertType = "Informational"
            Case ALERT_WARNING
                strAlertType = "Warning"
            Case ALERT_ERROR
                strAlertType = "Error"
            Case ALERT_CRITICAL
                strAlertType = "Error"
            Case Else
                strAlertType = "Informational"
        End Select

        strAlertXML = "<Alert Priority=" & Chr(34) & CStr(intPriority) & Chr(34) & " Type=" & Chr(34) & strAlertType & Chr(34) & " Category=" & Chr(34) & strAlertCategory & Chr(34) & " EventLog=" & Chr(34) & strEventLog & Chr(34) & " Id=" & Chr(34) & strEventId & Chr(34) & " Source=" & Chr(34) & strEventSource & Chr(34) & _
                       " EventCount=" & Chr(34) & strAlertEventCount & Chr(34) & " FirstOccurence=" & Chr(34) & ConvertDateToString(strAlertFirstOcurrenceDate) & Chr(34) & " LastOccurence= " & Chr(34) & ConvertDateToString(strAlertEventLastOcurrenceDate) & Chr(34) & " LastOccurrenceMessage = " & Chr(34) & strAlertEventLastOcurrenceMessage & Chr(34) & " DaysToMonitor = " & Chr(34) & cstr(intAlertEventDaysToMonitor) & Chr(34) & ">" & _
                      "<Objects><Object Type=" & Chr(34) & "System.Management.Automation.PSCustomObject" & Chr(34) & " >" & _
                      "<Property Name=" & Chr(34) & "Message" & Chr(34) & ">" & strAlertMessage & "</Property>" & _
                      IIf(Len(strAlertRecommendation) > 0, "<Property Name=" & Chr(34) & "Recommendation" & Chr(34) & ">" & strAlertRecommendation & "</Property>", "") & _
                      IIf(bSkipRootCauseDetection, "<Property Name=" & Chr(34) & "SkipRootCauseDetection" & Chr(34) & ">true</Property>", "") & _
                      "</Object></Objects>" & _
                      "</Alert>"
                      
        AddtoArray arrScriptedDiagXML, strAlertXML
    End If
    
End Sub

Sub WriteAlertsToScriptedDiagXML()
    Dim strScriptedDiagXMLFileName, objScriptedDiagXMLFile, strLine
    On Error Resume Next
    If Not IsEmpty(arrScriptedDiagXML) Then
        strScriptedDiagXMLFileName = ReplaceEnvVars("%COMPUTERNAME%_EventLogAlerts.XML")
        
        If objFSO.FileExists(strScriptedDiagXMLFileName) Then
            'If a alert file already exist, load the alerts from this file to arrScriptedDiagXML before overwriting the file
            AddScriptedDiagAlertsFromXML strScriptedDiagXMLFileName
        End If
        
        wscript.Echo "    Writing file : '" & strScriptedDiagXMLFileName & "'"
        Set objScriptedDiagXMLFile = objFSO.OpenTextFile(strScriptedDiagXMLFileName, ForWriting, True, OpenFileMode)
        objScriptedDiagXMLFile.WriteLine "<?xml version=""1.0""?><Root>"
        Err.Clear
        
        For Each strLine In arrScriptedDiagXML
            objScriptedDiagXMLFile.WriteLine strLine
            If Err.Number = 5 Then
                objScriptedDiagXMLFile.WriteLine RebuildASCIIString(strLine)
                Err.Clear
            End If
        Next
        
        objScriptedDiagXMLFile.WriteLine "</Root>"
        objScriptedDiagXMLFile.Close
    End If
End Sub

Sub AddScriptedDiagAlertsFromXML(strScriptedDiagXMLFileName)
        Dim objXMLDoc, objAlertinXML
        
        On Error Resume Next
        
        Set objXMLDoc = CreateObject("Microsoft.XMLDOM")
        objXMLDoc.async = "false"
        objXMLDoc.Load strScriptedDiagXMLFileName
        
        If (Not objXMLDoc Is Nothing) And (objXMLDoc.parseError.errorCode = 0) Then
            For Each objAlertinXML In objXMLDoc.getElementsByTagName("Root/Alert")
                AddtoArray arrScriptedDiagXML, objAlertinXML.xml
            Next
        Else
            If objXMLDoc.parseError.errorCode <> 0 Then
                DisplayXMLError objXMLDoc, "LoadScriptedDiagAlertsFromXML", "The file " & strScriptedDiagXMLFileName & " could not be loaded or it is invalid. Alert XML file will be ignored."
            Else
                DisplayError "Loading XML Alert File.", 5000, "LoadScriptedDiagAlertsFromXML", "The file " & strScriptedDiagXMLFileName & " could not be loaded or it is invalid. Alert XML file will be ignored."
            End If
        End If
End Sub

Function GetAgeDescription(datDateTime)
    On Error Resume Next
    Dim intAge, strAge
    intAge = DateDiff("d", datDateTime, Now)
    strAge = CStr(intAge) & " day"
    If intAge = 0 Then
        intAge = DateDiff("h", datDateTime, Now)
        If intAge > 0 Then
            strAge = CStr(intAge) & " hour"
        Else
            intAge = DateDiff("n", datDateTime, Now)
            If intAge > 0 Then
                strAge = CStr(intAge) & " minute"
            Else
                intAge = DateDiff("s", datDateTime, Now)
                strAge = CStr(intAge) & " second"
            End If
        End If
    End If

    If CDbl(Left(strAge, 2)) > 1 Then
        strAge = strAge & "s"
    End If
    
    GetAgeDescription = strAge
End Function

Function StringToArray(strString, strSeparator)
    On Error Resume Next
    Dim arrArray()
    ReDim arrArray(0)
    Dim intCommaPosition, intPreviousCommaPosition
    Dim strArrayMember
    intPreviousCommaPosition = 1
    
    intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
    
    Do While intCommaPosition <> 0
        strArrayMember = Trim(Replace(Mid(strString, intPreviousCommaPosition, intCommaPosition - intPreviousCommaPosition), Chr(34), ""))
        If Len(strArrayMember) > 0 Then
            If Len(arrArray(UBound(arrArray))) > 0 Then ReDim Preserve arrArray(UBound(arrArray) + 1)
            arrArray(UBound(arrArray)) = strArrayMember
        End If
        intPreviousCommaPosition = intCommaPosition + 1
        intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
    Loop
    
    strArrayMember = Trim(Replace(Mid(strString, intPreviousCommaPosition, Len(strString)), Chr(34), ""))
    If Len(strArrayMember) > 0 Then
        If Len(arrArray(UBound(arrArray))) > 0 Then ReDim Preserve arrArray(UBound(arrArray) + 1)
        arrArray(UBound(arrArray)) = strArrayMember
    End If
    
    StringToArray = arrArray
End Function

Sub GenerateOutput(strLogName)

    Dim intNumRecords, intLogSize, strLogType, strSourceEventLogPath, strLocalLogPath, bDataExist, bIsChannelLog, bIsLogEnabled
    Dim x, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert, datTimeStarted
    intNumRecords = 0
    strSourceEventLogPath = ""
    strLocalLogPath = ""
    bIsChannelLog = False
    bMonitorEvents = False

    On Error Resume Next

    If bGenerateSDP2Alert Or bGenerateScriptedDiagXMLAlerts Then
        'Check if there are any alert to monitor in the current event log
        For x = 0 To UBound(arrAlertEventLogtoMonitor)
            If LCase(arrAlertEventLogtoMonitor(x)) = LCase(strLogName) Then
                bMonitorEvents = True
                AddtoArray arrEventSourceToAlert, LCase(arrAlertEventSourcetoMonitor(x))
                AddtoArray arrEventIDtoAlert, CLng(arrAlertEventIDtoMonitor(x))
                AddtoArray arrEventDateToAlert, DateAdd("d", arrAlertEventDaysToMonitor(x) * -1, Now)
                bEventLogIncludesAlert = True
            End If
        Next
    End If
    
    If (bOSSupportChannels) Then
        If CheckWevtLogInfo(strLogName, intNumRecords, intLogSize, strLogType, strSourceEventLogPath, bIsChannelLog, bIsLogEnabled) Then
            bDataExist = ((LCase(strLogType) = "operational" Or LCase(strLogType) = "admin") And intNumRecords > 0) Or (LCase(strLogType) = "debug" And intLogSize > 4096)
            If bDataExist Then
                If Not ((LCase(strLogType) = "operational") Or (LCase(strLogType) = "admin")) Then
                    strLocalLogPath = CopyEventLogFile(strLogName, strSourceEventLogPath)
                End If
                If (bCSVOutput Or bTXTOutput Or bWEVTTXTOutput) Then
                    datTimeStarted = Timer
                    If (Not bUseWevtutil) And Not (bIsChannelLog) Then
                        OpenWMIService
                        intNumRecords = GenerateOutputfromWMI(strLogName, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)
                    Else
                        intNumRecords = GenerateOutputfromWevtUtil(strLogName, strLocalLogPath, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)
                    End If
                    If intNumRecords > 0 Then
                        Dim strRecordPerSecond
                        strRecordPerSecond = FormatNumber(intNumRecords / (Timer - datTimeStarted), 0)
                        If strRecordPerSecond = "0" Then
                            strRecordPerSecond = FormatNumber(intNumRecords / (Timer - datTimeStarted), 2)
                        End If
                        wscript.Echo "      Records processed per second: " & strRecordPerSecond & "."
                    End If
                End If
                
                If (bEVTXOutput Or bWEVTXMLOutput Or bETLOutput) And _
                   (((bCSVOutput Or bTXTOutput Or bWEVTTXTOutput) And (intNumRecords > 0)) Or _
                   Not (bCSVOutput Or bTXTOutput Or bWEVTTXTOutput)) Then
                    If bEVTXOutput Then
                        GenerateOutputtoEVTX strLogName, strLocalLogPath
                    End If
                    If bWEVTXMLOutput Then
                        GenerateOutputtoXML strLogName, strLocalLogPath
                    End If
                Else
                    If intNumRecords = 0 Then
                        wscript.Echo "      " & IIf(bFilterbyDays, "Filtered ", "") & strLogName & " event log contains 0 records. EVTX and/or XML not generated."
                    End If
                End If
                If Len(strLocalLogPath) > 0 And (Not bETLOutput) Then
                    objFSO.DeleteFile strLocalLogPath, True
                    If Err.Number <> 0 Then
                        wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": deleting '" & strLocalLogPath & "'."
                    End If
                End If
            Else
                wscript.Echo "      " & strLogName & " contains 0 records. No files generated."
            End If
        Else
            wscript.Echo "      EVTX, ETL and/or XML not generated for " & strLogName & " due error running wevtutil."
        End If
    Else
        OpenWMIService
        If (bCSVOutput Or bTXTOutput) Then
            datTimeStarted = Now
            intNumRecords = GenerateOutputfromWMI(strLogName, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)
            wscript.Echo "      Total records: " & CStr(intNumRecords) & ". Records processed per second: " & FormatNumber(intNumRecords / DateDiff("s", datTimeStarted, Now), 0) & "."
        End If
    End If
   
    wscript.Echo "      Operation completed."
    
End Sub

Function CopyEventLogFile(strLogName, strSourceLogPath)
    Dim strDestLogPath
    
    On Error Resume Next
    
    strDestLogPath = GetLogFileName(strLogName) & "." & objFSO.GetExtensionName(strSourceLogPath)
    
    If bETLOutput Then
        wscript.Echo ("      Copying to:   '" & objFSO.GetFileName(strDestLogPath) & "'.")
    Else
        wscript.Echo ("      Copying Debug/Analytic file.")
    End If

    If LCase(objFSO.GetExtensionName(strSourceLogPath)) = "evtx" Then 'Avoid naming conflict
        strDestLogPath = objFSO.GetBaseName(strEVTXFileName) & "_raw." & objFSO.GetExtensionName(strSourceLogPath)
    End If
    objFSO.CopyFile ReplaceEnvVars(strSourceLogPath), strDestLogPath, True 'Copy the file to local folder
    If Err.Number = 0 Then
        CopyEventLogFile = strDestLogPath
    Else
        CopyEventLogFile = ""
        wscript.Echo "    Error 0x" & HexFormat(Err.Number) & " when copying file " & strSourceLogPath & "."
    End If
End Function



Function CheckWevtLogInfo(strEventLogName, ByRef intNumRecords, ByRef intSize, ByRef strType, ByRef strLogFilename, ByRef bIsChannelLog, ByRef bIsLogEnabled)
    Dim strLine, bNumberRecordsExist, intReturnCode, bFileSizeExists
    bNumberRecordsExist = False
    bIsChannelLog = False
    
    On Error Resume Next
    
    intReturnCode = ShellExec("%COMSPEC% /c %WINDIR%\System32\wevtutil.exe gli " & Chr(34) & strEventLogName & Chr(34) & " & %WINDIR%\System32\wevtutil.exe gl " & Chr(34) & strEventLogName & Chr(34), "", True, False, True)
    If intReturnCode = 0 Then
        Do While Not objExec.StdOut.AtEndOfStream
            strLine = objExec.StdOut.ReadLine()
            If LCase(Left(strLine, 18)) = "numberoflogrecords" Then
               intNumRecords = CLng(Right(strLine, Len(strLine) - 19))
               bNumberRecordsExist = True
            End If
            If LCase(Left(strLine, 8)) = "filesize" Then
               intSize = CLng(Right(strLine, Len(strLine) - 9))
               bFileSizeExists = True
            End If
            If LCase(Left(strLine, 4)) = "type" Then
              strType = Right(strLine, Len(strLine) - 6)
              If (LCase(strType) <> "admin") Then bIsChannelLog = True
            End If
            If LCase(Left(strLine, 7)) = "enabled" Then
                bIsLogEnabled = CBool(Right(strLine, Len(strLine) - 9))
            End If
            If LCase(Left(strLine, 13)) = "  logfilename" Then
              strLogFilename = Right(strLine, Len(strLine) - 15)
            End If
        Loop
        objExec.StdOut.Close
        CheckWevtLogInfo = True
    Else
        wscript.Echo "Error " & CStr(intReturnCode) & " when running wevtutil. Please check if log " & strEventLogName & " exists and is enabled on local machine."
        CheckWevtLogInfo = False
    End If
    
    wscript.Echo "      Enabled: " & CStr(bIsLogEnabled) & " - Type: " & strType & IIf(intNumRecords <> 0, " - Total records: " & FormatNumber(intNumRecords, 0), "")
    If Not (bNumberRecordsExist) And Not (bFileSizeExists) Then intNumRecords = 0
    
End Function

Function ExportToWevtutilTXT(strLogName, strLogPath)
    
    Dim CmdLine, intResults, strLine, lngDiff

    If Len(strLogPath) = 0 Then
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe qe " & Chr(34) & strLogName & Chr(34) & " /f:Text /uni:false"
    Else
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe qe " & Chr(34) & strLogPath & Chr(34) & " /lf:true /f:Text /uni:false"
    End If
    
    If bFilterbyDays Then
        
        lngDiff = 86400000 * intNumberofDaystoFilter + (DateDiff("s", TimeSerial(0, 0, 0), Time) * 1000)
        CmdLine = CmdLine & " /q:" & Chr(34) & "*[System[TimeCreated[timediff(@SystemTime) <= " & CStr(lngDiff) & "]]]" & Chr(34)
        
    ElseIf bFilterQuery Then
        CmdLine = CmdLine & " /q:" & Chr(34) & strFilterQuery & Chr(34)
    End If
    
    ExportToWevtutilTXT = WevtutilShellExec(CmdLine, "", strLogName, True, False)

End Function

Function GenerateOutputtoEVTX(strLogName, strLogPath)
    Dim CmdLine, intResults, strLine, strBaseFileName, lngDiff

    strBaseFileName = GetLogFileName(strLogName)
    strEVTXFileName = strBaseFileName & ".evtx"
    On Error Resume Next
    
    wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strEVTXFileName) & ".evtx'"
    
    If objFSO.FileExists(strEVTXFileName) Then objFSO.DeleteFile strEVTXFileName, True
    If Err.Number <> 0 Then
        wscript.Echo "Error: File already exists. Error 0x" & HexFormat(Err.Number) & ": deleting '" & strEVTXFileName & "'."
        Exit Function
    End If
    
    If Not IsEmpty(objExec) Then
        While objExec.Status = 0
            wscript.Sleep 200
        Wend
    End If
    
    If Len(strLogPath) = 0 Then
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe epl " & Chr(34) & strLogName & Chr(34) & " " & Chr(34) & strEVTXFileName & Chr(34)
    Else
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe epl " & Chr(34) & strLogPath & Chr(34) & " " & Chr(34) & strEVTXFileName & Chr(34) & " /lf:true"
    End If
    
    If bFilterbyDays Then
        lngDiff = 86400000 * intNumberofDaystoFilter + (DateDiff("s", TimeSerial(0, 0, 0), Time) * 1000) 'We calculate the difference up to the 12:00AM
        CmdLine = CmdLine & " /q:" & Chr(34) & "*[System[TimeCreated[timediff(@SystemTime) <= " & CStr(lngDiff) & "]]]" & Chr(34)
    ElseIf bFilterQuery Then
        CmdLine = CmdLine & " /q:" & Chr(34) & strFilterQuery & Chr(34)
    End If
    
    intResults = WevtutilShellExec(CmdLine, "", strLogName, True, False)
    If intResults = 0 Then
        If bEvtxExtended Then
            While objExec.Status = 0
                wscript.Sleep 200
            Wend
            
            wscript.Echo "      Archiving file: '" & objFSO.GetBaseName(strEVTXFileName) & ".evtx'"
            CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe al " & Chr(34) & strEVTXFileName & Chr(34) & ""
            intResults = WevtutilShellExec(CmdLine, "", strLogName, True, False)
        End If
    End If
    
   If Not IsEmpty(objExec) Then
   			wscript.echo "      Waiting for WevtUtil..."
        While objExec.Status = 0
            wscript.Sleep 200
        Wend
    End If
    
    GenerateOutputtoEVTX = true
End Function

Function PostArchiveMainEventLogs()
    
    wscript.Echo ""
    wscript.Echo "Archiving main event logs..."
    
    Dim objEvents, objEventLog, bArchiveLog, x, CmdLine, intResults
    OpenWMIService
    Set objEvents = objWMIService.ExecQuery("Select * from Win32_NTEventLogFile", , 48)
    
    If Err.Number <> 0 Then
       wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": executing WMI query"
       wscript.Echo Err.Source & " - " & Err.Description
       wscript.Quit
    End If
    
    For Each objEventLog In objEvents
        bArchiveLog = True
        If bLogExclusionEnabled Then
            For x = 0 To UBound(arrLogExceptionList)
                If LCase(arrLogExceptionList(x)) = LCase(objEventLog.LogFileName) Then
                    bArchiveLog = False
                End If
            Next
        End If
        If bArchiveLog Then
            strEVTXFileName = GetLogFileName(objEventLog.LogFileName) & ".evtx"
            
            wscript.Echo "      Archiving file: '" & objFSO.GetBaseName(strEVTXFileName) & ".evtx'"
            
            CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe al " & Chr(34) & strEVTXFileName & Chr(34) & ""
            intResults = WevtutilShellExec(CmdLine, "", objEventLog.LogFileName, True, False)
            
            While objExec.Status = 0
                wscript.Sleep 200
            Wend
        Else
            wscript.Echo "      Skipping: '" & objEventLog.LogFileName & "'"
        End If
    Next
End Function

Function GenerateOutputtoXML(strLogName, strLogPath)
    Dim CmdLine, intResults, strLine, strBaseFileName, strFormat, lngDiff

    strBaseFileName = GetLogFileName(strLogName)
    strWEVTXMLFileName = strBaseFileName & ".XML"
    
    wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strWEVTXMLFileName) & ".XML'"
    
    If bXMLFormatRendered Then
        strFormat = "RenderedXML"
    Else
        strFormat = "XML"
    End If
    If Len(strLogPath) = 0 Then
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe qe " & Chr(34) & strLogName & Chr(34) & " /rd:true /f:" & strFormat & " /e:root "
    Else
        CmdLine = "%COMSPEC% /c %windir%\system32\wevtutil.exe qe " & Chr(34) & strLogPath & Chr(34) & " /lf:true /rd:true /f:" & strFormat & " /e:root "
    End If
    
    If bFilterbyDays Then
        lngDiff = 86400000 * intNumberofDaystoFilter + (DateDiff("s", TimeSerial(0, 0, 0), Time) * 1000)
        CmdLine = CmdLine & " /q:" & Chr(34) & "*[System[TimeCreated[timediff(@SystemTime) <= " & CStr(lngDiff) & "]]]" & Chr(34)
    ElseIf bFilterQuery Then
        CmdLine = CmdLine & " /q:" & Chr(34) & strFilterQuery & Chr(34)
    End If
    
    intResults = WevtutilShellExec(CmdLine, strWEVTXMLFileName, strLogName, False, True)
    
    GenerateOutputtoXML = intResults
End Function


Function WevtutilShellExec(strCommandLine, strOutputFile, strEventLogName, bNoWalkStdOut, bDeleteOutputIfLessThenThreeLines)
    Dim intReturnCode

    intReturnCode = ShellExec(strCommandLine, strOutputFile, bNoWalkStdOut, bDeleteOutputIfLessThenThreeLines, False)
    WevtutilShellExec = intReturnCode
    
    Select Case intReturnCode
      Case 0
      Case 15007 'ERROR_EVT_CHANNEL_NOT_FOUND
         wscript.Echo ""
         wscript.Echo "Error 0x" & HexFormat(intReturnCode) & " - ERROR_EVT_CHANNEL_NOT_FOUND running wevtutil.exe utility."
         wscript.Echo " - Check if the log '" & strEventLogName & "' exists"
         wscript.Echo "   and/ or is enabled in the current machine."
         wscript.Echo ""
         Exit Function
      Case 15001 'ERROR_EVT_INVALID_QUERY
         wscript.Echo ""
         wscript.Echo "Error 0x" & HexFormat(intReturnCode) & " - ERROR_EVT_INVALID_QUERY running wevtutil.exe utility."
         wscript.Echo " - Check if the query '" & strFilterQuery & "' is correct"
         Exit Function
    Case 15022 '
         wscript.Echo ""
         wscript.Echo "Error 0x" & HexFormat(intReturnCode) & " - when running wevtutil. The channel must first be disabled before running this command."
         Exit Function
    Case Else
        wscript.Echo ""
        wscript.Echo "Error 0x" & HexFormat(intReturnCode) & " running wevtutil.exe utility. Aborting..."
        If bFilterQuery Then
            wscript.Echo "Please check if the following query is correct: {" & strFilterQuery & "}"
        End If
        Exit Function
    End Select

End Function


Function ShellExec(strCommandLine, strOutputFile, bNoWalkStdOut, bDeleteOutputIfLessThenThreeLines, bWaituntilComplete)
        
    Dim objStdOutFile, strLine, intNumLines
    
    On Error Resume Next
    Set objExec = objShell.Exec(strCommandLine)
    
    If Len(strOutputFile) > 0 Then
        Set objStdOutFile = objFSO.OpenTextFile(strOutputFile, ForWriting, True, OpenFileMode)
    
        If Err.Number <> 0 Then
            wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
            wscript.Echo "   When creating the file " & strOutputFile
            wscript.Quit
        End If
    End If
    
    If (Not bNoWalkStdOut) Or (objExec.ExitCode <> 0) Then
        Do While Not objExec.StdOut.AtEndOfStream
            strLine = objExec.StdOut.ReadLine()
            If Len(strOutputFile) > 0 Then
                objStdOutFile.WriteLine strLine
                intNumLines = intNumLines + 1
            Else
                wscript.Echo strLine
            End If
        Loop
        If Len(strOutputFile) > 0 Then
            objStdOutFile.Close
            If Not bKeepEmptyFiles Then
                If bDeleteOutputIfLessThenThreeLines And intNumLines < 3 Then
                    wscript.Echo "      " & objFSO.GetFileName(strOutputFile) & " has 0 records - file removed."
                    objFSO.DeleteFile strOutputFile, True
                End If
            End If
        End If
    End If
    
    If bWaituntilComplete Then
        While objExec.Status = 0
            wscript.Sleep 50
        Wend
    End If
    
    ShellExec = objExec.ExitCode
    
    If Err.Number <> 0 Then
        DisplayError "Running command line " & strCommandLine, Err.Number, "ShellExec", Err.Description
        ShellExec = Err.Number
    End If
        
End Function

Function GetCurrentOSBuild()
    On Error Resume Next
    GetCurrentOSBuild = CInt(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber"))
End Function

Function IsSP1Beta()
    On Error Resume Next
    IsSP1Beta = (InStr(1, objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLab"), "rc", vbTextCompare) > 0)
End Function

Function OSSupportChannels()
    On Error Resume Next
    If CInt(Left(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion"), 1)) >= 6 Then
        OSSupportChannels = True
    Else
        OSSupportChannels = False
        bUseWevtutil = False
    End If
End Function

Function IIf(Expression, TruePart, FalsePart)
    If Expression Then
        IIf = TruePart
    Else
        IIf = FalsePart
    End If
End Function

Function GenerateOutputfromWevtUtil(strLogName, strLogPath, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)

    Dim strBaseFileName
    Dim objEvent, intReturnCode, intNumRecords
    Dim strCSVFileName, strTXTFileName
    
    Dim strTimeStart
    
    On Error Resume Next
          
    strTimeStart = Now
    
    strBaseFileName = GetLogFileName(strLogName)
    If (bCSVOutput) Then
        strCSVFileName = strBaseFileName & ".csv"
    End If
    If (bTXTOutput) Then
        strTXTFileName = strBaseFileName & ".txt"
    End If
    If bWEVTTXTOutput Then
       strWEVTTXTFileName = strBaseFileName & ".wevtutil.txt"
    End If
    
    intReturnCode = ExportToWevtutilTXT(strLogName, strLogPath)

    If intReturnCode = 0 Then
        If bWEVTTXTOutput Then
           wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strWEVTTXTFileName) & ".txt'"
           
           Set objWevtutilTXTFile = objFSO.OpenTextFile(strWEVTTXTFileName, ForWriting, True, OpenFileMode)
        
            If Err.Number <> 0 Then
                wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
                wscript.Echo "   When creating file " & strWEVTTXTFileName
                wscript.Quit
            End If
        End If
        
        If bCSVOutput Then
            wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strCSVFileName) & ".csv'"
            Set objCSVFile = objFSO.OpenTextFile(strCSVFileName, ForWriting, True, OpenFileMode)
        
            If Err.Number <> 0 Then
                wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
                wscript.Echo "   When creating file " & strCSVFileName
                wscript.Quit
            End If
        End If
        
        If bTXTOutput Then
            wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strTXTFileName) & ".txt'"
            Set objTXTFile = objFSO.OpenTextFile(strTXTFileName, ForWriting, True, OpenFileMode)
        
            If Err.Number <> 0 Then
                wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
                wscript.Echo "   When creating file " & strTXTFileName
                wscript.Quit
            End If
        End If
        
        WriteHeaderInFiles (strLogName)
        intNumRecords = 0
        GenerateTXTOutputfromWevtUtilTXTStdOut strLogName, intNumRecords, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert

        If bTXTOutput Then
            If Not bNoScriptStats Then
                If bNoTableFormatinTXT Then
                    objTXTFile.WriteLine "[Info]  [" & GetStatsEnd(strLogName, strTimeStart) & "]"
                    objTXTFile.WriteLine "[Info]  [" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
                Else
                    objTXTFile.WriteLine Space(24) & _
                                         IIf(bIncludeTimeGeneratedCol, Space(23), "") & " " & _
                                            Space(14) & _
                                            IIf(bIncludeComputerCol, Space(17), "") & _
                                            Space(8) & _
                                            IIf(bIncludeSourceCol, Space(36), "") & _
                                            IIf(bIncludeTaskCol, FormatStr("[Info]", 19), "") & _
                                            IIf(bIncludeUserCol, Space(34), "") & _
                                            IIf(bIncludeSIDCol, Space(48), "") & _
                                            "[" & GetStatsStart(strLogName, strTimeStart) & "]"
                    objTXTFile.WriteLine Space(24) & _
                                         IIf(bIncludeTimeGeneratedCol, Space(23), "") & " " & _
                                            Space(14) & _
                                            IIf(bIncludeComputerCol, Space(17), "") & _
                                            Space(8) & _
                                            IIf(bIncludeSourceCol, Space(36), "") & _
                                            IIf(bIncludeTaskCol, FormatStr("[Info]", 19), "") & _
                                            IIf(bIncludeUserCol, Space(34), "") & _
                                            IIf(bIncludeSIDCol, Space(48), "") & _
                                            "[" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
                End If
            End If
            objTXTFile.Close
            If (intNumRecords = 0) And Not bKeepEmptyFiles Then
                wscript.Echo "      " & objFSO.GetFileName(strTXTFileName) & " has 0 records - file removed."
                objFSO.DeleteFile strTXTFileName, True
            End If
        End If
    
        If bCSVOutput Then
            If Not bNoScriptStats Then
                objCSVFile.WriteLine ",," & _
                                      IIf(bIncludeTimeGeneratedCol, ",", "") & _
                                      "," & _
                                      IIf(bIncludeComputerCol, ",", "") & _
                                      "," & _
                                      IIf(bIncludeSourceCol, ",", "") & _
                                      IIf(bIncludeTaskCol, "[Info],", "") & _
                                      IIf(bIncludeUserCol, ",", "") & _
                                      IIf(bIncludeSIDCol, ",", "") & _
                                      "[" & GetStatsStart(strLogName, strTimeStart) & "]"
                objCSVFile.WriteLine ",," & _
                                      IIf(bIncludeTimeGeneratedCol, ",", "") & _
                                      "," & _
                                      IIf(bIncludeComputerCol, ",", "") & _
                                      "," & _
                                      IIf(bIncludeSourceCol, ",", "") & _
                                      IIf(bIncludeTaskCol, "[Info],", "") & _
                                      IIf(bIncludeUserCol, ",", "") & _
                                      IIf(bIncludeSIDCol, ",", "") & _
                                      "[" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
            End If
            objCSVFile.Close
            If (intNumRecords = 0) And Not bKeepEmptyFiles Then
                objFSO.DeleteFile strCSVFileName, True
                wscript.Echo "      " & objFSO.GetFileName(strCSVFileName) & " has 0 records - file removed."
            End If
        End If
        
        If bWEVTTXTOutput Then
            objWevtutilTXTFile.Close
            If (intNumRecords = 0) And Not bKeepEmptyFiles Then
                wscript.Echo "      " & objFSO.GetFileName(strWEVTTXTFileName) & " has 0 records - file removed."
                objFSO.DeleteFile strWEVTTXTFileName, True
            End If
        End If
    
        Err.Clear
    
        GenerateOutputfromWevtUtil = intNumRecords
    End If
End Function

Sub GenerateTXTOutputfromWevtUtilTXTStdOut(strLogName, ByRef intNumRecords, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)

    Dim strLogfile, strDate, strTime, strComputername, strEventCode, intEventCode, strEventTask, strSourceName, strLevel, strUser, strMessage
    Dim bFinishedRecord, strLine, strFieldName, intSeparator, strFieldValue, intLenStrline, x, datDateTime

    Dim strRow
    Dim strTimeStart
    Dim strChannelName
    Dim strSID
    Dim strWevtutilTimeGenerated
    
    intNumRecords = 0

    On Error Resume Next

    While Not objExec.StdOut.AtEndOfStream
        bFinishedRecord = False
        While (Not bFinishedRecord) And (Not objExec.StdOut.AtEndOfStream)
            strLine = objExec.StdOut.ReadLine()
            intLenStrline = Len(strLine)
            If bWEVTTXTOutput Then
                objWevtutilTXTFile.WriteLine strLine
            End If
            If intLenStrline > 0 Then
                intSeparator = InStr(6, strLine, ":")
                If intLenStrline <> intSeparator Then
                    strFieldName = Mid(strLine, 3, intSeparator - 3)
                    strFieldValue = Right(strLine, Len(strLine) - intSeparator - 1)
                    Select Case strFieldName
                        Case "Source"
                            If bIncludeSourceCol Then
                                strSourceName = strFieldValue
                            End If
                        Case "Date"
                            'strWevtutilTimeGenerated = Replace(strFieldValue, "T", " ", 1, 1)
                            strWevtutilTimeGenerated = strFieldValue
                        Case "Event ID"
                            strEventCode = strFieldValue
                            intEventCode = CLng(strFieldValue)
                        Case "Task"
                            If bIncludeTaskCol Then
                                strEventTask = strFieldValue
                            End If
                        Case "Level"
                                strLevel = strFieldValue
                        Case "User"
                            If bIncludeSIDCol Then
                                strSID = strFieldValue
                            End If
                        Case "User Name"
                            If bIncludeUserCol Then
                                strUser = strFieldValue
                            End If
                        Case "Computer"
                            If bIncludeComputerCol Then
                                strComputername = strFieldValue
                            End If
                        Case "Description"
                            Dim bFinishedDescription
                            bFinishedDescription = False
                            strMessage = ""
                            While (Not bFinishedDescription) And (Not objExec.StdOut.AtEndOfStream)
                                strLine = objExec.StdOut.ReadLine()
                                If bWEVTTXTOutput Then
                                    objWevtutilTXTFile.WriteLine strLine
                                End If
                                While strLine = "" And (Not objExec.StdOut.AtEndOfStream)
                                    strLine = objExec.StdOut.ReadLine
                                    If bWEVTTXTOutput Then
                                        objWevtutilTXTFile.WriteLine strLine
                                    End If
                                Wend
                                If Left(strLine, 6) <> "Event[" Then
                                    strMessage = strMessage & strLine & " "
                                Else
                                    bFinishedDescription = True
                                    bFinishedRecord = True
                                End If
                            Wend
                    End Select
                End If
            End If
        Wend

        If IsNull(strWevtutilTimeGenerated) Then
            strDate = "N/A"
            strTime = "N/A"
            strWevtutilTimeGenerated = "N/A"
        Else
             ConvertWevtUtilTimeCreatedToDateTime strWevtutilTimeGenerated, strDate, strTime, datDateTime
        End If
        
        If bIncludeComputerCol Then
            If IsNull(strComputername) Then
                strComputername = "N/A"
            End If
        End If
        
        If bIncludeUserCol Then
            If IsNull(strUser) Then
                strUser = "N/A"
            End If
        End If
        
        If bIncludeSIDCol Then
            If IsNull(strSID) Then
                strSID = "N/A"
            End If
        End If

        If IsNull(strEventCode) Then
            strUser = "None"
        End If

        If bIncludeSourceCol Then
            If IsNull(strSourceName) Then
                strSourceName = "N/A"
            End If
        End If
        
        If IsNull(strLevel) Then
            strLevel = "N/A"
        End If

        If bIncludeTaskCol Then
            If IsNull(strEventTask) Then
                strEventTask = "None"
            End If
        End If

        If bMonitorEvents Then
            For x = 0 To UBound(arrEventSourceToAlert)
                If arrEventIDtoAlert(x) = intEventCode Then
                    If arrEventDateToAlert(x) < datDateTime Then
                        If LCase(strSourceName) = arrEventSourceToAlert(x) Then
                            IncrementAlertCount strLogName, datDateTime, arrEventIDtoAlert(x), arrEventSourceToAlert(x), ConvertLevelToEventType(strLevel), strMessage, strComputername
                        End If
                    End If
                End If
            Next
        End If

        If bCSVOutput Then
            strRow = strDate & "," & _
                     strTime & "," & _
                     IIf(bIncludeTimeGeneratedCol, strWevtutilTimeGenerated & ",", "") & _
                     strLevel & "," & _
                     IIf(bIncludeComputerCol, strComputername & ",", "") & _
                     strEventCode & "," & _
                     IIf(bIncludeSourceCol, strSourceName & ",", "") & _
                     IIf(bIncludeTaskCol, strEventTask & ",", "") & _
                     IIf(bIncludeUserCol, strUser & ",", "") & _
                     IIf(bIncludeSIDCol, strSID & ",", "")
            If bShowQuotesinCSV Then
                strRow = strRow & Chr(34) & Replace(strMessage, Chr(34), "'") & Chr(34) 'Replace double quotes with single quotes
            Else
                strRow = strRow & strMessage
            End If
            objCSVFile.WriteLine strRow
        End If

        If bTXTOutput Then
            If bNoTableFormatinTXT Then
                strRow = strDate & " " & _
                     strTime & "  " & _
                     IIf(bIncludeTimeGeneratedCol, strWevtutilTimeGenerated & " ", "") & _
                     strLevel & " " & _
                     IIf(bIncludeComputerCol, strComputername & " ", "") & _
                     strEventCode & " " & _
                     IIf(bIncludeSourceCol, strSourceName & " ", "") & _
                     IIf(bIncludeTaskCol, strEventTask & " ", "") & _
                     IIf(bIncludeUserCol, strUser & " ", "") & _
                     IIf(bIncludeSIDCol, strSID & " ", "") & _
                     strMessage
            Else
                strRow = strDate & " " & _
                     strTime & "  " & _
                     IIf(bIncludeTimeGeneratedCol, strWevtutilTimeGenerated, "") & " " & _
                     FormatStr(strLevel, 13) & " " & _
                     IIf(bIncludeComputerCol, FormatStr(strComputername, 16) & " ", "") & _
                     FormatStr(CStr(strEventCode), 7) & " " & _
                     IIf(bIncludeSourceCol, FormatStr(strSourceName, 35) & " ", "") & _
                     IIf(bIncludeTaskCol, FormatStr(strEventTask, 18) & " ", "") & _
                     IIf(bIncludeUserCol, FormatStr(strUser, 33) & " ", "") & _
                     IIf(bIncludeSIDCol, FormatStr(strSID, 47) & " ", "") & _
                     strMessage
            End If
            objTXTFile.WriteLine strRow
        End If
               
        If Err.Number = 0 Then
             intNumRecords = intNumRecords + 1
        Else
            Err.Clear
        End If
    Wend
    
    objExec.StdOut.Close
    
End Sub

Sub ConvertWevtUtilTimeCreatedToDateTime(ByVal strFullDateTime, ByRef strDate, ByRef strTime, ByRef datDateTime)
    Dim hr, mnsec, ampm
    
    hr = Mid(strFullDateTime, 12, 2)
    If hr >= 12 Then
      If hr <> 12 Then
          hr = CStr(hr - 12)
      End If
      ampm = "PM"
    Else
      ampm = "AM"
      If hr = 0 Then hr = 12
    End If
    hr = Right("0" & hr, 2)
    
    mnsec = Mid(strFullDateTime, 15, 5)
    
    strDate = Mid(strFullDateTime, 6, 2) & "/" & Mid(strFullDateTime, 9, 2) & "/" & Left(strFullDateTime, 4)
    
    datDateTime = DateSerial(Left(strFullDateTime, 4), Mid(strFullDateTime, 6, 2), Mid(strFullDateTime, 9, 2)) + TimeSerial(Mid(strFullDateTime, 12, 2), Mid(strFullDateTime, 15, 2), Mid(strFullDateTime, 18, 2))
    
    strTime = hr & ":" & mnsec & " " & ampm
End Sub

Function ConvertLevelToEventType(strLevel)
    Select Case strLevel
        Case "Information"
            ConvertLevelToEventType = 3
        Case "Warning"
            ConvertLevelToEventType = 2
        Case "Error"
            ConvertLevelToEventType = 1
        Case Else
            ConvertLevelToEventType = 4
    End Select
End Function

Function GetLogFileName(strLogName)
    
    Dim intSpacePos, strFolderName, strFileName, strShortFileName, intLastDashPos
       
    strShortFileName = strLogName
    
    Dim intSlashPos
    intSlashPos = InStr(1, strShortFileName, "/")
    If intSlashPos = 0 Then
        intSlashPos = InStr(1, strShortFileName, "-")
    End If
    If intSlashPos > 0 Then 'Name contains '/' or "-"
        strShortFileName = Replace(strLogName, "Microsoft-Windows-", "")
        strShortFileName = Replace(strShortFileName, "Microsoft-", "")
        strShortFileName = Replace(strShortFileName, "/", "-")
        strShortFileName = Replace(strShortFileName, ".", "")
        intLastDashPos = InStrRev(strShortFileName, "-")
        strShortFileName = Replace(Left(strShortFileName, intLastDashPos), "-", "") & Right(strShortFileName, Len(strShortFileName) - intLastDashPos + 1)
    End If
    
    strFileName = strPrefixforFilenames & Replace(strShortFileName, " ", "") & strSuffixforFilenames
    
    If Len(strOutputFolder) > 0 Then
        GetLogFileName = objFSO.BuildPath(strOutputFolder, strFileName)
    Else
        GetLogFileName = objFSO.BuildPath(objFSO.GetAbsolutePathName("."), strFileName)
    End If
    
End Function

Function GenerateOutputfromWMI(strLogName, bMonitorEvents, arrEventSourceToAlert, arrEventIDtoAlert, arrEventDateToAlert)
    Dim strBaseFileName, strWMIQuery
    Dim objEventLog, objEvent, strInsertionString
    Dim strRow, intNumRecords, x
    Dim strCSVFileName, strTXTFileName
    Dim strTimeStart, timeStarted
    
    On Error Resume Next
    
    intNumRecords = 0
    strTimeStart = Now
    timeStarted = Timer
    
    strBaseFileName = GetLogFileName(strLogName)
    If (bCSVOutput) Then
        strCSVFileName = strBaseFileName & ".csv"
    End If
    If (bTXTOutput) Then
        strTXTFileName = strBaseFileName & ".txt"
    End If
    
    If bCSVOutput Then
        wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strCSVFileName) & ".csv'"
        Set objCSVFile = objFSO.OpenTextFile(strCSVFileName, ForWriting, True, OpenFileMode)
    
        If Err.Number <> 0 Then
            wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
            wscript.Echo "   When opening the file " & strCSVFileName
            wscript.Quit
        End If
    End If
    
    If bTXTOutput Then
        wscript.Echo "      Exporting to: '" & objFSO.GetBaseName(strTXTFileName) & ".txt'"
        Set objTXTFile = objFSO.OpenTextFile(strTXTFileName, ForWriting, True, OpenFileMode)
    
        If Err.Number <> 0 Then
            wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": " & Err.Source & " - " & Err.Description
            wscript.Echo "   When opening the file " & strTXTFileName
            wscript.Quit
        End If
    End If
    
    'wscript.Echo "      Running WMI query..."
    strWMIQuery = "Select TimeGenerated, ComputerName, User, EventCode, SourceName, CategoryString, Category, Type, EventType, Message, InsertionStrings from Win32_NTLogEvent where Logfile='" & strLogName & "'"
        
    If bFilterbyDays Then
        Dim strStartDate, strMonth, strDay
        strStartDate = CStr(DateDiff("d", intNumberofDaystoFilter, Now))
        strDay = Right("0" & CStr(Day(strStartDate)), 2)
        strMonth = Right("0" & CStr(Month(strStartDate)), 2)
        strWMIQuery = strWMIQuery & " and TimeGenerated>='" & _
                      CStr(Year(strStartDate)) & strMonth & strDay & "'"
    ElseIf bFilterQuery Then
        If Not ((LCase(Left(strFilterQuery, 3)) = "and") Or (LCase(Trim(Left(strFilterQuery, 4))) = "and")) Then
            strWMIQuery = strWMIQuery & " and " & strFilterQuery
        Else
            strWMIQuery = strWMIQuery & " " & strFilterQuery
        End If
    End If
    
    Set objEventLog = objWMIService.ExecQuery(strWMIQuery, , 48)

    If Err.Number <> 0 Then
       wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": when opening event log '" & strLogName & "' via WMI"
       wscript.Echo Err.Source & " - " & Err.Description
    Else
        WriteHeaderInFiles (strLogName)
                
        Dim strLogfile, strDate, strTime, strComputername, strEventCode, strEventCategory, strSourceName, strType, strUser, strMessage, datDateTime, intEventCode
        
        For Each objEvent In objEventLog
            'strLogfile = objEvent.Logfile
            
            If IsNull(objEvent.TimeGenerated) Then
                strDate = "N/A"
                strTime = "N/A"
            Else
                ConvertWMIDateTime objEvent.TimeGenerated, strDate, strTime, datDateTime
            End If
                   
            If IsNull(objEvent.ComputerName) Then
                strComputername = "N/A"
            Else
                strComputername = objEvent.ComputerName
            End If
            
            If IsNull(objEvent.User) Then
                strUser = "N/A"
            Else
                strUser = objEvent.User
            End If
            
            If IsNull(objEvent.EventCode) Then
                strEventCode = "None"
            Else
                strEventCode = objEvent.EventCode
                intEventCode = CLng(objEvent.EventCode)
            End If
                    
            If IsNull(objEvent.SourceName) Then
                strSourceName = "N/A"
            Else
                strSourceName = objEvent.SourceName
            End If
            
            If IsNull(objEvent.CategoryString) Then
                If objEvent.Category <> 0 Then
                    strEventCategory = "{" & objEvent.Category & "}"
                Else
                    strEventCategory = "N/A"
                End If
                If strEventCategory = "{0}" Then strEventCategory = "None"
            Else
                strEventCategory = objEvent.CategoryString
            End If
                      
            
            If IsNull(objEvent.Type) Then
                strType = "None"
            Else
                strType = objEvent.Type
                If Len(strType) = 0 Then
                    'For any reason, the objEvent.Type contains an empty string.
                    'the most commom case is an information record.
                    If objEvent.EventType = 0 Then
                        strType = "Information"
                    Else
                        strType = "{" & CStr(objEvent.EventType) & "}"
                    End If
                End If
            End If
            
            If IsNull(objEvent.Message) Then
                'If there is no message, let's try to obtain the InsertionStrings
                strMessage = ""
                If Not IsNull(objEvent.InsertionStrings) Then
                    For Each strInsertionString In objEvent.InsertionStrings
                        strMessage = strMessage & strInsertionString & ", "
                    Next
                End If
                If strMessage = "" Then
                    strMessage = "N/A"
                Else
                    strMessage = "{" & Left(strMessage, Len(strMessage) - 2) & "}" 'Remove last ', '
                    strMessage = FilterCtrlChars(strMessage)
                End If
            Else
                strMessage = FilterCtrlChars(objEvent.Message)
            End If
            
            If bMonitorEvents Then
                For x = 0 To UBound(arrEventSourceToAlert)
                    If arrEventIDtoAlert(x) = intEventCode Then
                        If arrEventDateToAlert(x) < datDateTime Then
                            If LCase(strSourceName) = arrEventSourceToAlert(x) Then
                                IncrementAlertCount strLogName, datDateTime, arrEventIDtoAlert(x), arrEventSourceToAlert(x), objEvent.EventType, strMessage, strComputername
                            End If
                        End If
                    End If
                Next
            End If
            
            If bCSVOutput Then
                strRow = strDate & "," & _
                         strTime & "," & _
                         strType & "," & _
                         strComputername & "," & _
                         strEventCode & "," & _
                         strSourceName & "," & _
                         strEventCategory & "," & _
                         strUser & ","
                If bShowQuotesinCSV Then
                    strRow = strRow & Chr(34) & Replace(strMessage, Chr(34), "'") & Chr(34) 'Replace double quotes with single quotes
                Else
                    strRow = strRow & strMessage
                End If
                objCSVFile.WriteLine strRow
                If Err.Number = 5 Then
                    'For any reason, we failed here - most likely an invalid char.
                    'In this case, we try to rebuild the string only with ASCII chars.
                    Err.Clear
                    objCSVFile.WriteLine RebuildASCIIString(strRow)
                End If
            End If
        
            If bTXTOutput Then
                If bNoTableFormatinTXT Then
                    strRow = strDate & " " & _
                         strTime & "  " & _
                         strType & " " & _
                         strComputername & " " & _
                         strEventCode & " " & _
                         strSourceName & " " & _
                         strEventCategory & " " & _
                         strUser & " " & _
                         strMessage
                Else
                    strRow = strDate & " " & _
                         strTime & "  " & _
                         FormatStr(strType, 13) & " " & _
                         FormatStr(strComputername, 16) & " " & _
                         FormatStr(CStr(strEventCode), 7) & " " & _
                         FormatStr(strSourceName, 32) & " " & _
                         FormatStr(strEventCategory, 15) & " " & _
                         FormatStr(strUser, 34) & " " & _
                         strMessage
                End If
                objTXTFile.WriteLine strRow
                If Err.Number = 5 Then
                    'For any reason, we failed to write the line here - most likely an invalid or unicode char.
                    'We try to rebuild the string only with ASCII chars.
                    Err.Clear
                    objTXTFile.WriteLine RebuildASCIIString(strRow)
                End If
            End If
            If Err.Number = 0 Then
                 intNumRecords = intNumRecords + 1
            End If
            Err.Clear
        Next
    End If

    wscript.Echo "      Operation completed in " & FormatNumber(Timer - timeStarted, 0) & " seconds."

    If bCSVOutput Then
        If Not bNoScriptStats Then
            objCSVFile.WriteLine ",,,,,,[Info],,[" & GetStatsStart(strLogName, strTimeStart) & "]"
            objCSVFile.WriteLine ",,,,,,[Info],,[" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
        End If
        objCSVFile.Close
        If (intNumRecords = 0) And Not bKeepEmptyFiles Then
            objFSO.DeleteFile strCSVFileName, True
            wscript.Echo "      " & objFSO.GetFileName(strCSVFileName) & " has 0 records - file removed."
        End If
    End If
    
    If bTXTOutput Then
        If Not bNoScriptStats Then
            If bNoTableFormatinTXT Then
                objTXTFile.WriteLine "[Info]  [" & GetStatsEnd(strLogName, strTimeStart) & "]"
                objTXTFile.WriteLine "[Info]  [" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
            Else
                objTXTFile.WriteLine Space(96) & _
                                     "[Info]      " & Space(39) & _
                                     "[" & GetStatsStart(strLogName, strTimeStart) & "]"
                objTXTFile.WriteLine Space(96) & _
                                     "[Info]      " & Space(39) & _
                                     "[" & GetStatsEnd(intNumRecords, strTimeStart) & "]"
            End If
        End If
        objTXTFile.Close

        If (intNumRecords = 0) And Not bKeepEmptyFiles Then
            objFSO.DeleteFile strTXTFileName, True
            wscript.Echo "      " & objFSO.GetFileName(strTXTFileName) & " has 0 records - file removed."
        End If
    End If
    
    GenerateOutputfromWMI = intNumRecords
End Function

Sub IncrementAlertCount(strLogName, datDateTime, strEventID, strSourceName, intEventType, strMessage, strComputername)
    'Add a new alert or increment the alert count
    
    'First locate the alert
    
    Dim x
    
    For x = 0 To UBound(arrAlertEventLogtoMonitor)
        If LCase(arrAlertEventLogtoMonitor(x)) = LCase(strLogName) Then
            If LCase(arrAlertEventSourcetoMonitor(x)) = strSourceName Then
                If CLng(arrAlertEventIDtoMonitor(x)) = strEventID Then
                    arrAlertEventCount(x) = arrAlertEventCount(x) + 1
                    If arrAlertEventLastOcurrenceDate(x) < datDateTime Then
                        arrAlertEventLastOcurrenceDate(x) = datDateTime
                        arrAlertEventLastOcurrenceMessage(x) = strMessage
                        arrAlertEventType(x) = CLng(intEventType)
                        arrAlertEventComputername(x) = strComputername
                        If arrAlertFirstOcurrenceDate(x) > datDateTime Then
                            arrAlertFirstOcurrenceDate(x) = datDateTime
                        End If
                    Else
                        arrAlertFirstOcurrenceDate(x) = datDateTime
                    End If
                End If
            End If
        End If
    Next
End Sub

Function BackupEventLog(strLogName)
    On Error Resume Next
    
    Dim strOutputName, objLogFiles, objLogFile
    
    OpenWMIService
    Set objLogFiles = objWMIService.ExecQuery _
        ("Select Name, Extension from Win32_NTEventLogFile where LogFileName='" & strLogName & "'")
    
    If Err.Number = 0 Then
        For Each objLogFile In objLogFiles
            strOutputName = GetLogFileName(strLogName) & "." & objLogFile.Extension
            wscript.Echo "      Making backup to '" & objFSO.GetFileName(strOutputName) & "'"
            If objFSO.FileExists(strOutputName) Then objFSO.DeleteFile strOutputName, True
            
            objLogFile.BackupEventLog (strOutputName)
            
            If Err.Number <> 0 Then
                DisplayError "Backup'ing event log " & strLogName & " to " & strOutputName, Err.Number, "BackupEventLog", Err.Description
                Err.Clear
            End If
        Next
    Else
        DisplayError "Opening opening Win32_NTEventLogFile (" & strLogName & " log).", Err.Number, "BackupEventLog", Err.Description
        Err.Clear
    End If
End Function

Function ReplaceEnvVars(strString)
    Dim intFirstPercentPos, intSecondPercentPos
    Dim strEnvVar
    intFirstPercentPos = InStr(1, strString, "%")
    
    While intFirstPercentPos > 0
        intSecondPercentPos = InStr(intFirstPercentPos + 1, strString, "%")
        If intSecondPercentPos > 0 Then
            strEnvVar = Mid(strString, intFirstPercentPos + 1, intSecondPercentPos - intFirstPercentPos - 1)
            strString = Replace(strString, "%" & strEnvVar & "%", objShell.Environment("PROCESS").Item(strEnvVar))
            intFirstPercentPos = InStr(1, strString, "%")
        Else
            intFirstPercentPos = 0
        End If
    Wend
    ReplaceEnvVars = strString
End Function


Function RebuildASCIIString(strString)
    Dim x
    For x = 1 To Len(strString)
        RebuildASCIIString = RebuildASCIIString & Chr(Asc(Mid(strString, x, 1)))
    Next
End Function

Function FormatStr(strValue, NumberofChars)
    If Len(strValue) > NumberofChars Then
        FormatStr = Left(strValue, NumberofChars)
    Else
        FormatStr = strValue + Space(NumberofChars - Len(strValue))
    End If
End Function

Function ConvertWMIDateTime(ByVal WmiDatetime, ByRef strDate, ByRef strTime, ByRef datDateTime)
    Dim dtUTCDateTime, dtLocalDateTime, hr, ampm, mn, sec
    dtUTCDateTime = DateSerial(Left(WmiDatetime, 4), Mid(WmiDatetime, 5, 2), Mid(WmiDatetime, 7, 2)) + _
                    TimeSerial(Mid(WmiDatetime, 9, 2), Mid(WmiDatetime, 11, 2), Mid(WmiDatetime, 13, 2))
        
    If intCurrentBiasfromWMIDateTime = -1 Then
        intCurrentBiasfromWMIDateTime = -(CInt(Right(WmiDatetime, 4)) + intCurrentTzBias)
    End If
    dtLocalDateTime = DateAdd("n", intCurrentBiasfromWMIDateTime, dtUTCDateTime)
    datDateTime = dtLocalDateTime
    hr = Hour(dtLocalDateTime)
    If hr >= 12 Then
      If hr <> 12 Then
          hr = CStr(hr - 12)
          hr = Right("0" & hr, 2)
      End If
      ampm = "PM"
    Else
      ampm = "AM"
      If hr = "0" Then
        hr = "12"
      Else
        hr = Right("0" & hr, 2)
      End If
    End If
    
    mn = Right("0" & Minute(dtLocalDateTime), 2)
    sec = Mid(WmiDatetime, 13, 2)
    
    strDate = Right("0" & Month(dtLocalDateTime), 2) & "/" & Right("0" & Day(dtLocalDateTime), 2) & "/" & CStr(Year(dtLocalDateTime))
    strTime = hr & ":" & mn & ":" & sec & " " & ampm
End Function

Function ObtainTimeZoneBias()
    ' Obtain local Time Zone bias from machine registry.
    Dim lngBiasKey, lngBias, k
    
    lngBiasKey = objShell.RegRead("HKLM\System\CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias")
      
    If UCase(TypeName(lngBiasKey)) = "LONG" Then
      lngBias = lngBiasKey
    ElseIf UCase(TypeName(lngBiasKey)) = "VARIANT()" Then
      lngBias = 0
      For k = 0 To UBound(lngBiasKey)
        lngBias = lngBias + (lngBiasKey(k) * 256 ^ k)
      Next
    End If
    ObtainTimeZoneBias = lngBias
End Function

Function GetTimeZoneName()

    On Error Resume Next

    Dim objEvents, objEventLog

    If strTimeZoneName = "" Then

        OpenWMIService
        Set objEvents = objWMIService.ExecQuery("Select *, Caption from Win32_TimeZone", , 48)
        
        If Err.Number <> 0 Then
           wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": executing WMI query to obtain Time Zone information."
           wscript.Echo Err.Source & " - " & Err.Description
           Exit Function
        End If
        
        For Each objEventLog In objEvents
            strTimeZoneName = objEventLog.Caption
            GetTimeZoneName = strTimeZoneName
        Next
        
        If Err.Number <> 0 Then
            wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": processing WMI data to obtain Time Zone information."
            wscript.Echo Err.Source & " - " & Err.Description
        End If
        
    Else
    
        GetTimeZoneName = strTimeZoneName
    
    End If
End Function

Function GetStatsStart(strLogName, strTimeStart)
    Dim strTimeZone
    
    On Error Resume Next
    
    strTimeZone = GetTimeZoneName
    
    GetStatsStart = "Export operation started at '" & CStr(strTimeStart) & _
                "' - Log Name: '" & strLogName & _
                "' - Machine Name: '" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                "' - Username: '" & objShell.Environment("PROCESS").Item("USERNAME") & _
                IIf(Len(strTimeZone) > 0, "' - TimeZone: '" & strTimeZone & "'", "")

    If bFilterbyDays Then
        Dim strStartDate, strEndDate, strStartDateDisplay, strStartTimeDisplay
        strStartDate = DateAdd("n", (intNumberofDaystoFilter * -60), Now)
        strStartDateDisplay = Month(strStartDate) & "\" & Day(strStartDate) & "\" & Year(strStartDate)
        strStartTimeDisplay = TimeValue(strStartDate)
        GetStatsStart = GetStatsStart & " - Events filtered from '" & strStartDateDisplay & " " & strStartTimeDisplay & "'"
    End If
    
    If bFilterQuery Then
        GetStatsStart = GetStatsStart & " - Filter query: '" & strFilterQuery & "'"
    End If
    
End Function

Function GetStatsEnd(NumberOfRecords, strTimeStart)
    GetStatsEnd = "Export operation ended at '" & _
                CStr(Now) & "' - " & _
                CStr(FormatNumber(NumberOfRecords, 0)) & " record(s) generated. " & _
                "Operation completed in " & CStr(FormatNumber(DateDiff("s", strTimeStart, Now), 0)) & " second(s)."
End Function

Sub WriteHeaderInFiles(strLogName)
    Dim strRow
    
    If bCSVOutput Then
        objCSVFile.WriteLine "Date,Time," & _
                              IIf(bIncludeTimeGeneratedCol, "Time Generated,", "") & _
                              "Type/Level,Computer Name,Event Code," & _
                               IIf(bIncludeSourceCol, "Source,", "") & _
                               IIf(bIncludeTaskCol, "Task Category,", "") & _
                               IIf(bIncludeUserCol, "Username,", "") & _
                               IIf(bIncludeSIDCol, "Sid,", "") & _
                               "Description"
    End If
    
    If bTXTOutput Then
        If Not bNoHeaderinTXT Then
            If bShowCtrlChars Then
                objTXTFile.WriteLine "Ctrl Chars Replacement Keys"
                objTXTFile.WriteLine "============================"
                objTXTFile.WriteLine "  (cr)  = Carrige returns"
                objTXTFile.WriteLine "  (lf)  = Line Feeds"
                objTXTFile.WriteLine "  (ff)  = Form feeds"
                objTXTFile.WriteLine "  (tab) = Tabs"
                objTXTFile.WriteBlankLines (1)
            End If
        End If
        If Not bUseWevtutil Then
            If bNoTableFormatinTXT Then
                objTXTFile.WriteLine "Date Time Type ComputerName EventCode Source Category Username Description"
            Else
                objTXTFile.WriteLine "Date       " & _
                                  "Time         " & _
                                  "Type/Level    " & _
                                  "ComputerName     " & _
                                  "Event   " & _
                                  "Source                           " & _
                                  "Task Category   " & _
                                  "Username                           " & _
                                  "Message"
                objTXTFile.WriteLine String(165, "-")
            End If
        Else
            If bNoTableFormatinTXT Then
                objTXTFile.WriteLine "Date Time " & _
                                       IIf(bIncludeTimeGeneratedCol, "Time Generated", "") & _
                                       "Type " & _
                                       IIf(bIncludeComputerCol, "ComputerName ", "") & _
                                       "EventID " & _
                                       IIf(bIncludeSourceCol, "Source ", "") & _
                                       IIf(bIncludeTaskCol, "Category ", "") & _
                                        IIf(bIncludeUserCol, "Username ", "") & _
                                        IIf(bIncludeSIDCol, "Sid ", "") & _
                                       "Description"
            Else
                strRow = "Date       " & _
                            "Time         " & _
                            IIf(bIncludeTimeGeneratedCol, FormatStr("Time Generated", 23), "") & " " & _
                            FormatStr("Type/Level", 13) & " " & _
                            IIf(bIncludeComputerCol, FormatStr("Computer Name", 16) & " ", "") & _
                            FormatStr("EventID", 8) & "" & _
                            IIf(bIncludeSourceCol, FormatStr("Source", 35) & " ", "") & _
                            IIf(bIncludeTaskCol, FormatStr("Task Category", 18) & " ", "") & _
                            IIf(bIncludeUserCol, FormatStr("Username", 34), "") & _
                            IIf(bIncludeSIDCol, FormatStr("Sid", 48), "") & _
                            "Message"
                objTXTFile.WriteLine strRow
                objTXTFile.WriteLine String(Len(strRow) + 70, "-")
            End If
        End If
    End If
End Sub

Function FilterCtrlChars(ByVal strMessage)

    If bShowCtrlChars Then
        strMessage = Replace(strMessage, vbCrLf, "(cr)(lf)")
        strMessage = Replace(strMessage, vbCr, "(cr)")
        strMessage = Replace(strMessage, vbTab, "(tab)")
        strMessage = Replace(strMessage, vbLf, "(lf)")
        strMessage = Replace(strMessage, Chr(0), "(null)")
        strMessage = Replace(strMessage, vbFormFeed, "(ff)")
    Else
        If Not bUseWevtutil Then
            strMessage = Replace(strMessage, vbCr, " ")
            strMessage = Replace(strMessage, vbTab, " ")
            strMessage = Replace(strMessage, Chr(0), " ")
            strMessage = Replace(strMessage, vbFormFeed, " ")
            'strMessage = Replace(strMessage, vbCrLf, " ")
        End If
        strMessage = Replace(strMessage, vbLf, " ")
    End If
    
    FilterCtrlChars = strMessage
    
End Function

Function DetectScriptEngine()
    Dim ScriptHost
    ScriptHost = wscript.FullName
    ScriptHost = Right(ScriptHost, Len(ScriptHost) - InStrRev(ScriptHost, "\"))
    If (UCase(ScriptHost) <> "CSCRIPT.EXE") Then
          lineOut ""
        lineOut "This script runs under CSCRIPT.EXE only." & vbCr & "Script aborting." & vbCr
        DetectScriptEngine = False
    Else
        DetectScriptEngine = True
    End If
End Function

Function ValidateArguments()

    'Validate Command Line Arguments
    'This function returns 0 if everything is ok or
    'returns a string with error helper

    Dim x, bErrorValidation, bError, stradditionalError, strArgument
    
    bArgumentsContainOutput = False
    
    bShowCtrlChars = False
    bShowQuotesinCSV = True
    bCSVOutput = False
    bTXTOutput = False
    bGenerateAllWMIEvents = False
    bNoTableFormatinTXT = False
    bFilterbyDays = False
    bNoScriptStats = False
    bKeepEmptyFiles = False
    bIncludeTimeGeneratedCol = False
    bIncludeSIDCol = False
    bIncludeUserCol = True
    bIncludeComputerCol = True
    bIncludeSourceCol = True
    bIncludeTaskCol = True
    bFilterQuery = False
    bEvtxExtended = True
    bWEVTXMLOutput = False
    bEVTOutput = False
    bEVTXOutput = False
    bEventLogIncludesAlert = False
    
    bWEVTTXTOutput = False
    bXMLFormatRendered = False
    bLogExclusionEnabled = False
    bArgumentFileEnabled = False
    bForceMTAFiles = False
    
    strPrefixforFilenames = DEFAULTPREFIXFORFILENAMES
    strSuffixforFilenames = ""
    
    ReDim arrEventLogNames(0)
    
    strFilterQuery = ""
    
    On Error Resume Next
    
    intNumberofDaystoFilter = 0
    bPostArchiveMainEventLogs = False
    
    Dim arrArgumentList
    
    If (wscript.Arguments.Count >= 1) Then
        ValidateArguments = 0
        ReDim arrArgumentList(wscript.Arguments.Count - 1)
        For x = 0 To wscript.Arguments.Count - 1
            arrArgumentList(x) = wscript.Arguments(x)
        Next
        ProcessArgumentList arrArgumentList, bError, stradditionalError
                
        If bError Then
            ValidateArguments = stradditionalError
        End If
    End If
        
End Function

Function ProcessArgumentList(arrArguments, ByRef bError, ByRef stradditionalError)
    
    Dim x, strArgument
    
    On Error Resume Next
    
    For x = 0 To UBound(arrArguments)
        strArgument = arrArguments(x)
        Select Case LCase(strArgument)
            Case "/evtx"
                bEVTXOutput = True
                If bOSSupportChannels Then bArgumentsContainOutput = True
            Case "/evt"
                bEVTOutput = True
                If Not bOSSupportChannels Then bArgumentsContainOutput = True
            Case "/etl"
                bETLOutput = True
                If bOSSupportChannels Then bArgumentsContainOutput = True
            Case "/xml"
                bWEVTXMLOutput = True
                If bOSSupportChannels Then bArgumentsContainOutput = True
            Case "/wevtutiltxt"
                bWEVTTXTOutput = True
                If bOSSupportChannels Then bArgumentsContainOutput = True
            Case "/rendered"
                bXMLFormatRendered = True
            Case "/showcontrolchars"
                bShowCtrlChars = True
            Case "/nocsvquotes"
                bShowQuotesinCSV = False
            Case "/notable"
                bNoTableFormatinTXT = True
            Case "/noheader"
                bNoHeaderinTXT = True
            Case "/nostats", "/noscriptstats"
                bNoScriptStats = True
            Case "/keepemptylogs"
                bKeepEmptyFiles = True
            Case "/archivemainlogsonly"
                bPostArchiveMainEventLogs = True
            Case "/noextended"
                bEvtxExtended = False
            Case "/timegencol"
                bIncludeTimeGeneratedCol = True
            Case "/sidcol"
                bIncludeSIDCol = True
            Case "/nousercol"
                bIncludeUserCol = False
            Case "/nocomputercol"
                bIncludeComputerCol = False
            Case "/nosourcecol"
                bIncludeSourceCol = False
            Case "/notaskcol"
                bIncludeTaskCol = False
            Case "/allwmi"
                bGenerateAllWMIEvents = True
            Case "/forcemta"
                bForceMTAFiles = True
            Case "/sdp2alert"
                bGenerateSDP2Alert = True
            Case "/generatescripteddiagxmlalerts"
                bGenerateScriptedDiagXMLAlerts = True
            Case "/allevents"
                If bOSSupportChannels Then
                    bGenerateAllEvents = True
                Else
                    bGenerateAllWMIEvents = True
                End If
            Case Else
                If LCase(Left(strArgument, 5)) = "/days" Then
                    bFilterbyDays = True
                    intNumberofDaystoFilter = cDbl(Right(strArgument, Len(strArgument) - 6)) - 1
                ElseIf LCase(strArgument) = "/channel" Then
                    bUseWevtutil = bOSSupportChannels
                ElseIf LCase(Left(strArgument, 6)) = "/query" Then
                    bFilterQuery = True
                    strFilterQuery = Right(strArgument, Len(strArgument) - 7)
                ElseIf LCase(Left(strArgument, 7)) = "/prefix" Then
                    strPrefixforFilenames = Right(strArgument, Len(strArgument) - 8)
                ElseIf LCase(Left(strArgument, 7)) = "/suffix" Then
                    strSuffixforFilenames = Right(strArgument, Len(strArgument) - 8)
                ElseIf LCase(Left(strArgument, 4)) = "/log" Then
                    arrEventLogNames(UBound(arrEventLogNames)) = Right(strArgument, Len(strArgument) - 5)
                    ReDim Preserve arrEventLogNames(UBound(arrEventLogNames) + 1)
                ElseIf LCase(Left(strArgument, 7)) = "/except" Then
                    bLogExclusionEnabled = True
                    If IsEmpty(arrLogExceptionList) Then
                        arrLogExceptionList = StringToArray(Right(strArgument, Len(strArgument) - 8), ",")
                    Else
                        Dim arrLogExceptionListAdd, y
                        arrLogExceptionListAdd = StringToArray(Right(strArgument, Len(strArgument) - 8), ",")
                        If Not IsEmpty(arrLogExceptionListAdd) Then
                            For y = 0 To UBound(arrLogExceptionListAdd)
                                ReDim Preserve arrLogExceptionList(UBound(arrLogExceptionList) + 1)
                                arrLogExceptionList(UBound(arrLogExceptionList)) = arrLogExceptionListAdd(y)
                            Next
                            Erase arrLogExceptionListAdd
                        End If
                    End If
                ElseIf LCase(Left(strArgument, 9)) = "/alertxml" Then
                    AddAlertToMonitorFromXML (Right(strArgument, Len(strArgument) - 10))
                ElseIf LCase(Left(strArgument, 6)) = "/alert" Then
                    AddAlertToMonitor (Right(strArgument, Len(strArgument) - 7))
                ElseIf LCase(Left(strArgument, 10)) = "/arguments" Then
                    'Non documented: Sets a file location with user arguments
                    bArgumentFileEnabled = True
                    strArgumentFileFilePath = Right(strArgument, Len(strArgument) - 11)
                Else
                    Select Case LCase(Right(strArgument, 4))
                        Case "/csv"
                            bCSVOutput = True
                            bArgumentsContainOutput = True
                        Case "/txt"
                            bTXTOutput = True
                            bArgumentsContainOutput = True
                        Case Else
                            'It may be the event log name or Output Folder
                            'it could be one of these arguments: strEventLogName or strOutputFolder. Let's check:
                            If Len(strOutputFolder) = 0 Then
                                If objFSO.FolderExists(strArgument) Then
                                    strOutputFolder = objFSO.GetFolder(strArgument)
                                Else
                                    arrEventLogNames(UBound(arrEventLogNames)) = strArgument
                                    ReDim Preserve arrEventLogNames(UBound(arrEventLogNames) + 1)
                                End If
                            Else
                                arrEventLogNames(UBound(arrEventLogNames)) = strArgument
                                ReDim Preserve arrEventLogNames(UBound(arrEventLogNames) + 1)
                            End If
                    End Select
                End If
        End Select
    Next
    If UBound(arrEventLogNames) > 0 Then ReDim Preserve arrEventLogNames(UBound(arrEventLogNames) - 1)
    If Not bError Then
            'Everything seams to be ok, now we need to validate the syntax
        If Not (bTXTOutput Or bCSVOutput Or bWEVTXMLOutput Or bWEVTTXTOutput Or bEVTXOutput Or bEVTOutput Or bETLOutput) Then
            bError = True
            stradditionalError = "You need to provide one of these arguments: " & vbCrLf & _
                                 "/csv, /txt, /xml, /wevtutiltxt, /etl, /evt or /evtx "
        ElseIf (Not (bGenerateAllWMIEvents Or bGenerateAllEvents)) And (Len(arrEventLogNames(0)) = 0) Then
            bError = True
            stradditionalError = "You did not use the /allevents or /allwmi argument, in this case" & vbCrLf & _
                                 "you need to provide an Event log name." & vbCrLf & _
                                 "Please provide an event log name such System or Application"
        ElseIf (bGenerateAllWMIEvents Or bGenerateAllEvents) And (Len(arrEventLogNames(0)) > 0) Then
            bError = True
            stradditionalError = "You have specified both arguments: /allevents or /allwmi and" & vbCrLf & _
                                 "a invalid argument or log name : '" & arrEventLogNames(0) & "'" & vbCrLf & _
                                 "When using /allevents or /allwmi argument, no not use an event log name."
        ElseIf bGenerateAllEvents And bGenerateAllWMIEvents Then
            bError = True
            stradditionalError = "You specified both arguments: '/allwmi' and '/allevents'" & vbCrLf & _
                                 "These two parameters are incompatible to be used together."
        ElseIf Not (bUseWevtutil) And (bForceMTAFiles) Then
            bError = True
            stradditionalError = "You specified the '/forcemta' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/forcemta' argument, please use '/channel' as well."
        ElseIf Not (bUseWevtutil) And (Not bIncludeTaskCol) Then
            bError = True
            stradditionalError = "You specified the '/notaskcol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/notaskcol' argument, please use '/channel' as well."
        ElseIf Not (bUseWevtutil) And (Not bIncludeSourceCol) Then
            bError = True
            stradditionalError = "You have specified the '/nosourcecol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/nosourcecol' argument, please use '/channel' as well."
        ElseIf bFilterQuery And bFilterbyDays Then
            bError = True
            stradditionalError = "You have specified the '/query:' and '/days:' arguments." & vbCrLf & _
                                 "These arguments are incompatible when used together."
        ElseIf Not (bUseWevtutil) And (Not bIncludeComputerCol) Then
            bError = True
            stradditionalError = "You have specified the '/nocomputercol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/nocomputercol' argument, please use '/channel' as well."
        ElseIf Not (bUseWevtutil) And (Not bIncludeUserCol) Then
            bError = True
            stradditionalError = "You have specified the '/nousercol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/nousercol' argument, please use '/channel' as well."
        ElseIf Not (bUseWevtutil) And (bIncludeSIDCol) Then
            bError = True
            stradditionalError = "You have specified the '/sidcol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/sidcol' argument, please use '/channel' as well."
        ElseIf Not (bUseWevtutil) And (bIncludeTimeGeneratedCol) Then
            bError = True
            stradditionalError = "You have specified the '/timegencol' argument but no '/channel.'" & vbCrLf & _
                                 "When using '/timegencol' argument, please use '/channel' as well."
        ElseIf (bNoTableFormatinTXT) And Not (bTXTOutput) Then
            bError = True
            stradditionalError = "You have specified /notable argument, but no TXT output to be generated." & vbCrLf & _
                                 "Please use the /notable output only for txt outputs."
        ElseIf Not (bCSVOutput) And Not (bShowQuotesinCSV) Then
            bError = True
            stradditionalError = "You have specified /noquotes argument, but no CSV output to be generated." & vbCrLf & _
                                 "Please use the /noquotes output only for CSV outputs."
        ElseIf Not (bTXTOutput) And bNoHeaderinTXT Then
            bError = True
            stradditionalError = "You have specified /noheader argument, but no TXT output to be generated." & vbCrLf & _
                                 "Please use the /noheader output only for TXT outputs."
        ElseIf Not (bShowCtrlChars) And bNoHeaderinTXT Then
            bError = True
            stradditionalError = "You have specified /noheader argument, but did not use the /showcontrolchars." & vbCrLf & _
                                 "The /noheader is to be used only when using /showcontrolchars."
        ElseIf (bXMLFormatRendered) And (Not bWEVTXMLOutput) Then
            bError = True
            stradditionalError = "You have specified /rendered argument, but did not use the /xml." & vbCrLf & _
                                 "The /rendered is to be used only when using /xml argument."
        ElseIf bLogExclusionEnabled And (Not (bGenerateAllWMIEvents Or bGenerateAllEvents Or (UBound(arrEventLogNames) = 1))) Then
            bError = True
            stradditionalError = "You used /except argument but did not use /allevents or /allwmi argument," & vbCrLf & _
                                 "or selected only one log to export." & vbCrLf & _
                                 "Please use /allevents, /allwmi or several /log arguments when using /except."
            Erase arrLogExceptionList
            bLogExclusionEnabled = False
        ElseIf bFilterbyDays And (intNumberofDaystoFilter = -1) Then
            bError = True
            stradditionalError = "You used /days argument, but did not specify the number of days" & vbCrLf & _
                                 "or set the number of days to 0." & vbCrLf & _
                                 "Please use /days:{NumberofDays}, with a value bigger than 0."
        ElseIf (bLogExclusionEnabled) And Not (IsArray(arrLogExceptionList)) Then
            bError = True
            stradditionalError = "You have specified /except argument, but did not use a list of." & vbCrLf & _
                                 "logs to exclude from the /allwmi or /allevents." & vbCrLf & _
                                 "Please use /except:{List} as example in the help."
        ElseIf bGenerateSDP2Alert And Not IsArray(arrAlertEventLogtoMonitor) Then
            bGenerateSDP2Alert = False
        ElseIf bGenerateScriptedDiagXMLAlerts And Not IsArray(arrAlertEventLogtoMonitor) Then
            bGenerateScriptedDiagXMLAlerts = False
        ElseIf IsArray(arrAlertEventLogtoMonitor) And Not (bGenerateSDP2Alert Or bGenerateScriptedDiagXMLAlerts) Then
            bError = True
            stradditionalError = "You have specified /alert argument. In order to use /alert argument" & vbCrLf & _
                                 "you must use the /sdp2alert  or /eventlogalertxml flag."
        ElseIf (bGenerateSDP2Alert) And Not (bTXTOutput Or bCSVOutput Or bWEVTTXTOutput) Then
            bError = True
            stradditionalError = "You have specified /alert argument. This argument can be used only if also" & vbCrLf & _
                                 "exporting event logs to text file formats. Please add /txt or /csv arguments to command line."
            bGenerateSDP2Alert = False
            bGenerateScriptedDiagXMLAlerts = False
        ElseIf bFilterbyDays And Not (bTXTOutput Or bCSVOutput Or bWEVTTXTOutput) And bEVTOutput And Not (bOSSupportChannels) Then
            bError = True
            stradditionalError = "You have specified /days argument. For pre-Vista, this argument can be used only if also" & vbCrLf & _
                                 "exporting event logs to text file formats. Please add /txt or /csv arguments to command line."
            bFilterbyDays = False
        ElseIf bFilterbyDays And Not (bTXTOutput Or bCSVOutput Or bWEVTTXTOutput) And bEVTXOutput And bOSSupportChannels And Not bUseWevtutil Then
            bError = True
            stradditionalError = "You have specified /days argument. For Vista+, this argument can be used only when " & vbCrLf & _
                                 "exporting event logs to text file formats or when using wevtutil to export Event Logs." & vbCrLf & _
                                 "Please add /txt or /csv arguments to command line or use the /channel argument."
            bUseWevtutil = False
        End If
    End If
End Function

Sub AddAlertToMonitor(strAlertArgument)
    
    Dim arrArguments
    Dim strAlertEventLogtoMonitor, strAlertEventDaysToMonitor, strAlertEventSourcetoMonitor, strAlertEventIDtoMonitor, strAlertEventMoreInformation
    
    'Argument should be on format:
    'EventLog;Days;Source;ID;KB

    On Error Resume Next

    arrArguments = Split(strAlertArgument, ",")
    
    If IsArray(arrArguments) Then
        If Not IsEmpty(arrArguments) Then
        
            strAlertEventLogtoMonitor = arrArguments(0)
            strAlertEventDaysToMonitor = CInt(arrArguments(1))
            strAlertEventSourcetoMonitor = arrArguments(2)
            strAlertEventIDtoMonitor = CLng(arrArguments(3))
            If UBound(arrArguments) > 3 Then
                strAlertEventMoreInformation = arrArguments(4)
            Else
                strAlertEventMoreInformation = ""
            End If
            
            If Err.Number = 0 Then
                If Not CheckForDuplicatesAlerts(strAlertEventLogtoMonitor, strAlertEventSourcetoMonitor, strAlertEventIDtoMonitor) Then
                    AddtoArray arrAlertEventLogtoMonitor, strAlertEventLogtoMonitor
                    AddtoArray arrAlertEventDaysToMonitor, strAlertEventDaysToMonitor
                    AddtoArray arrAlertEventSourcetoMonitor, strAlertEventSourcetoMonitor
                    AddtoArray arrAlertEventIDtoMonitor, strAlertEventIDtoMonitor
                    AddtoArray arrAlertEventMoreInformation, strAlertEventMoreInformation
                    AddtoArray arrAlertEventCount, 0
                    AddtoArray arrAlertEventLastOcurrenceDate, CDate("1/1/2000")
                    AddtoArray arrAlertFirstOcurrenceDate, CDate("1/1/3000")
                    AddtoArray arrAlertEventType, 0
                    AddtoArray arrAlertEventLastOcurrenceMessage, ""
                    AddtoArray arrAlertEventComputername, ""
                    'For arguments, we don't have 'Section' and 'SectionPriority'. In this case, we fallback to Default.
                    AddtoArray arrAlertSection, "Event Log Messages"
                    AddtoArray arrAlertSectionPriority, 20
                Else
                    DisplayError "Processing alert element from an argument.", 5000, "AddAlertToMonitor", "An event log rule for " & strAlertEventLogtoMonitor & " event log, event source " & strAlertEventSourcetoMonitor & " ID " & strAlertEventIDtoMonitor & " was already added previously." & vbCrLf & vbCrLf & "  -- This alert will be ignored. Please check for duplicated event log rules."
                    Err.Clear
                End If

            Else
                DisplayError "Processing an alert argument", Err.Number, "AddAlertToMonitor", "'" & Err.Description & "' error when processing the following alert argument:" & vbCrLf & vbCrLf & " /alert:" & strAlertArgument & vbCrLf & vbCrLf & "  -- This alert will be ignored."
                Err.Clear
            End If
        End If
    End If
    
End Sub

Sub AddAlertToMonitorFromXML(strXMLPath)
    
    'Here is an example of a XML used for an alert:
    '<?xml version='1.0'?>
    '<Alerts>
    '   <Section>
    '       <SectionName></SectionName>
    '       <SectionPriority></SectionPriority>
    '       <Alert>
    '           <EventLog></EventLog>
    '          <Days></Days>
    '           <Source></Source>
    '           <ID></ID>
    '           <AdditionalInformation></AdditionalInformation>
    '       </Alert>
    '   </Section>
    '</Alerts>
    
    Dim objXMLDoc
    Dim objObjElement
    Dim objXMLFile
    Dim objXMLAlertNode
    Dim objChildNode
    Dim strAlertEventLogtoMonitor, strAlertEventDaysToMonitor, strAlertEventSourcetoMonitor, strAlertEventIDtoMonitor
    Dim strAlertEventMoreInformation, strAlertSection, intAlertSectionPriority
    
    On Error Resume Next

    Err.Clear
    
    wscript.Echo "Using alert rule xml file: '" & UCase(objFSO.GetFileName(strXMLPath)) & "'"
    
    If objFSO.FileExists(strXMLPath) Then
        
        Set objXMLDoc = CreateObject("Microsoft.XMLDOM")
        objXMLDoc.async = "false"
        objXMLDoc.Load strXMLPath

        If (Not objXMLDoc Is Nothing) And (objXMLDoc.parseError.errorCode = 0) Then
            For Each objXMLAlertNode In objXMLDoc.getElementsByTagName("Alerts/Section/Alert")
                strAlertSection = ""
                intAlertSectionPriority = 50
                strAlertSection = objXMLAlertNode.selectNodes("../SectionName").Item(0).Text
                intAlertSectionPriority = CInt(objXMLAlertNode.selectNodes("../SectionPriority").Item(0).Text)
                Err.Clear
                If Len(strAlertSection) = 0 Then strAlertSection = "Event Log Messages"
                strAlertEventLogtoMonitor = objXMLAlertNode.selectNodes("EventLog").Item(0).Text
                strAlertEventDaysToMonitor = CInt(objXMLAlertNode.selectNodes("Days").Item(0).Text)
                strAlertEventSourcetoMonitor = objXMLAlertNode.selectNodes("Source").Item(0).Text
                strAlertEventIDtoMonitor = CLng(objXMLAlertNode.selectNodes("ID").Item(0).Text)
                
                if isnull(objXMLAlertNode.selectNodes("AdditionalInformation").Item(0).xml) = false then 
                    strAlertEventMoreInformation = objXMLAlertNode.selectNodes("AdditionalInformation").Item(0).xml
                    'Remove the <AdditionalInformation></AdditionalInformation> tags from XML string
                    if Len(strAlertEventMoreInformation) > 25 then
                        strAlertEventMoreInformation = Right(strAlertEventMoreInformation, Len(strAlertEventMoreInformation) - 23)
                        strAlertEventMoreInformation = Left(strAlertEventMoreInformation, Len(strAlertEventMoreInformation) - 24)
                    else
                        strAlertEventMoreInformation = ""
                    end if
                else
                    strAlertEventIDtoMonitor = ""
                    strAlertEventMoreInformation = ""
                end if
                strAlertSkipRootCauseDetection = (instr(1, objXMLAlertNode.xml, ("<SkipRootCauseDetection")) > 0)

                If Err.Number = 0 Then
                    If Not CheckForDuplicatesAlerts(strAlertEventLogtoMonitor, strAlertEventSourcetoMonitor, strAlertEventIDtoMonitor) Then
                        AddtoArray arrAlertSection, strAlertSection
                        AddtoArray arrAlertSectionPriority, intAlertSectionPriority
                        AddtoArray arrAlertEventLogtoMonitor, strAlertEventLogtoMonitor
                        AddtoArray arrAlertEventDaysToMonitor, strAlertEventDaysToMonitor
                        AddtoArray arrAlertEventSourcetoMonitor, strAlertEventSourcetoMonitor
                        AddtoArray arrAlertEventIDtoMonitor, strAlertEventIDtoMonitor
                        AddtoArray arrAlertEventMoreInformation, strAlertEventMoreInformation
                        AddtoArray arrAlertSkipRootCauseDetection, strAlertSkipRootCauseDetection
                        AddtoArray arrAlertEventCount, 0
                        AddtoArray arrAlertEventLastOcurrenceDate, CDate("1/1/2000")
                        AddtoArray arrAlertFirstOcurrenceDate, CDate("1/1/3000")
                        AddtoArray arrAlertEventType, 0
                        AddtoArray arrAlertEventLastOcurrenceMessage, ""
                        AddtoArray arrAlertEventComputername, ""
                    Else
                        DisplayError "Processing a XML alert element.", 5000, "AddAlertToMonitorFromXML", "An event log rule for " & strAlertEventLogtoMonitor & " event log, event source " & strAlertEventSourcetoMonitor & " ID " & strAlertEventIDtoMonitor & " was already added previously." & vbCrLf & vbCrLf & "  -- This alert will be ignored. Please check for duplicated event log rules"
                        Err.Clear
                    End If
                Else
                    DisplayError "Processing a XML alert file element", Err.Number, "AddAlertToMonitorFromXML", "'" & Err.Description & "' error when processing the following element on " & strXMLPath & ": " & vbCrLf & vbCrLf & objXMLAlertNode.xml & vbCrLf & vbCrLf & "  -- This alert will be ignored. Please check if XML file and values are consistent"
                    Err.Clear
                End If
            Next
        Else
            If objXMLDoc.parseError.errorCode <> 0 Then
                DisplayXMLError objXMLDoc, "AddAlertToMonitorFromXML", "The file " & strXMLPath & " could not be loaded or it is invalid. Alert XML file will be ignored."
            Else
                DisplayError "Loading XML Alert File.", 5000, "AddAlertToMonitorFromXML", "The file " & strXMLPath & " could not be loaded or it is invalid. Alert XML file will be ignored."
            End If
        End If
    Else
        DisplayError "Loading XML File", 2, "AddAlertToMonitorFromXML", "The file " & strXMLPath & " does not exist."
    End If
End Sub

Function CheckForDuplicatesAlerts(strAlertEventLogtoMonitor, strAlertEventSourcetoMonitor, strAlertEventIDtoMonitor)
    Dim x
    CheckForDuplicatesAlerts = False
    If IsArray(arrAlertEventSourcetoMonitor) Then
        For x = 0 To UBound(arrAlertEventSourcetoMonitor)
            If (LCase(arrAlertEventSourcetoMonitor(x)) = LCase(strAlertEventSourcetoMonitor)) And (LCase(arrAlertEventIDtoMonitor(x)) = LCase(strAlertEventIDtoMonitor)) And (LCase(arrAlertEventLogtoMonitor(x)) = LCase(strAlertEventLogtoMonitor)) Then
                CheckForDuplicatesAlerts = True
                Exit Function
            End If
        Next
    End If
End Function

Function DisplayXMLError(xmlFile, strSourceFunction, strMessage)
    Dim strErrText
    On Error Resume Next
    If xmlFile.parseError.errorCode <> 0 Then
        With xmlFile.parseError
            strErrText = "Failed to process/ load XML file " & _
                    "due the following error:" & vbCrLf & vbCrLf & _
                    "   Error #: " & .errorCode & ": " & .reason & _
                    "   Line #: " & .Line & vbCrLf & _
                    "   Line Position: " & .linepos & vbCrLf & _
                    "   Position In File: " & .filepos & vbCrLf & _
                    "   Source Text: " & .srcText & vbCrLf & _
                    "   Document URL: " & .url
            DisplayXMLError = .errorCode
        End With
        DisplayError strMessage, 5000, strSourceFunction, strErrText
    End If
End Function

Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
    On Error Resume Next
    If errNumber <> 0 Then
        wscript.Echo "Error 0x" & HexFormat(errNumber) & IIf(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        wscript.Echo errSource & " - " & errDescription
    Else
        wscript.Echo "An error has ocurred. " & IIf(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        If (Len(errSource) > 0) Or (Len(errDescription) > 0) Then
            wscript.Echo errSource & " - " & errDescription
        End If
    End If
    wscript.Echo ""
End Sub

Function HexFormat(intNumber)
    HexFormat = Right("00000000" & CStr(Hex(intNumber)), 8)
End Function

Sub lineOut(strMsg)
        strBuffer = strBuffer & strMsg & vbCrLf
        If bolDisplayMsg Then
            wscript.Echo strBuffer
            strBuffer = ""
        End If
End Sub

Sub ShowArgumentsSyntax(strAdditionalInfo)

    wscript.Echo "Error: Invalid or missing arguments."
    wscript.Echo ""
    wscript.Echo strAdditionalInfo
    wscript.Echo ""
    wscript.Echo " Use:"
    wscript.Echo "   cscript " & wscript.ScriptName & " /allevents {OutputFormat} [Options]"
    wscript.Echo ""
    wscript.Echo "   [or]"
    wscript.Echo ""
    wscript.Echo "   cscript " & wscript.ScriptName & " /allwmi {OutputFormat} [Options]"
    wscript.Echo ""
    wscript.Echo "   [or]"
    wscript.Echo ""
    wscript.Echo "   cscript " & wscript.ScriptName & " {EventLogName} {OutputFormat} [Options]"
    wscript.Echo ""
    wscript.Echo "   [or]"
    wscript.Echo ""
    wscript.Echo "   cscript " & wscript.ScriptName & " {EventLogName} /channel {OutputFormat} [Options]"
    wscript.Echo "   [or]"
    wscript.Echo ""
    wscript.Echo ""
    wscript.Echo "   cscript " & wscript.ScriptName & " /LOG:{EventLogName} [/LOG:{...}] {OutputFormat} [Options]"
    wscript.Echo ""
    wscript.Echo " Where:"
    wscript.Echo ""
    wscript.Echo "    /allevents     = Generate output for all events logs"
    wscript.Echo "                     in the current machine."
    wscript.Echo "    /allwmi        = Generate output for all events logs exposed by WMI "
    wscript.Echo "                     in the current machine."
    wscript.Echo "                     This does not include the crimson-type event logs."
    wscript.Echo "    /channel       = Force wevtutil the engine used to export Event Logs."
    wscript.Echo "                     This argument is valid only in Windows Vista or newest."
    wscript.Echo ""
    wscript.Echo "    [OutputFolder] = Folder to save the txt and/or csv output"
    wscript.Echo "                     if not specified, files will be generated"
    wscript.Echo "                     in the current folder."
    wscript.Echo "    {EventLogName} = Name of Event Log in the local machine."
    wscript.Echo ""
    wscript.Echo "  {OutputFormat} can be one or more of the following arguments:"
    wscript.Echo ""
    wscript.Echo "    /txt           = Generate output in TXT format."
    wscript.Echo "    /csv           = Generate output in CSV format."
    wscript.Echo "    /evt           = For pre-Vista OSs, backup event logs in EVT format"
    wscript.Echo "                     Warning: The EVT generated will not be filtered,"
    wscript.Echo "                              meaning the /days and related arguments"
    wscript.Echo "                              will be ignored for this format."
    wscript.Echo "    /evtx          = Output in EVTX format."
    wscript.Echo "                     This argument is valid only in Windows Vista or newest."
    wscript.Echo "    /etl           = For Debug-type event logs, copy the ETL files."
    wscript.Echo "                     This argument is valid only in Windows Vista or newest."
    wscript.Echo "    /xml           = Output in Wevtutil/XML format."
    wscript.Echo "                     This argument is valid only in Windows Vista or newest."
    wscript.Echo "    /wevtutiltxt   = Output in Wevtutil/TXT format."
    wscript.Echo "                     The file generated will have the .wevtutil.txt extension."
    wscript.Echo "                     This argument is valid only in Windows Vista or newest."
    wscript.Echo ""
    wscript.Echo "  [Options] can be:"
    wscript.Echo ""
    wscript.Echo "    /days:{NumberofDays} = Filter events by date, where the output file will"
    wscript.Echo "                           contain only events from last {NumberofDays} days."
    wscript.Echo "    /nostats             = Do not add script statistics to the TXT and CSV files"
    wscript.Echo "    /showcontrolchars    = Translate the event description control chars as:"
    wscript.Echo "                               (tab) for Tabs "
    wscript.Echo "                               (cr) for Carriage returns"
    wscript.Echo "                               (ff) for Form Feeds"
    wscript.Echo "                               (lf) for Line Feeds"
    wscript.Echo "                           otherwise these chars will be replaced for spaces."
    wscript.Echo "    /noheader            = Do not display a description of the control chars"
    wscript.Echo "                           in first lines of txt file when /showcontrolchars"
    wscript.Echo "                           is used."
    wscript.Echo "    /notable             = Generate the txt output as plain text instead"
    wscript.Echo "                           of table format."
    wscript.Echo "    /nocsvquotes         = Do not add double quotes in description field"
    wscript.Echo "                           for CSV output."
    wscript.Echo "    /query:{Query}       = Query for filtering event logs."
    wscript.Echo "                           When used with /channel, {Query} is a wevtutil"
    wscript.Echo "                           compatible query."
    wscript.Echo "                           When not used with /channel, {Query} is a WMI"
    wscript.Echo "                           'where' compatible query."
    wscript.Echo "                           This argument is not compatible with /days argument."
    wscript.Echo "    /except:{List}       = Do not generate output for {List} logs."
    wscript.Echo "                           Where {List} is a list of logs separated by comma."
    wscript.Echo "                           This argument is valid only in conjunction with"
    wscript.Echo "                           /allevents or /allwmi arguments."
    wscript.Echo "    /rendered            = When using the /xml argument, the output generated"
    wscript.Echo "                           will be in Wevtutil/RenderedXML format"
    wscript.Echo "                           This argument is valid only in conjunction with /xml"
    wscript.Echo "    /noextended          = When using the /evtx argument, the output generated"
    wscript.Echo "                           will not contain extended data (MTA files)."
    wscript.Echo "                           This argument is valid only in conjunction with /evtx"
    wscript.Echo "    /prefix:[prefix]     = Set the prefix for generating file names."
    wscript.Echo "                           The default for prefix is " & DEFAULTPREFIXFORFILENAMES & "."
    wscript.Echo "    /suffix:[suffix]     = Set the sufix for generating file names."
    wscript.Echo "                           The default for prefix is empty."
    wscript.Echo ""
    wscript.Echo "    Exclusive options when using the /channel argument:"
    wscript.Echo ""
    wscript.Echo "    /timegencol    = Include wevtutil Time Generated column in the reporting file."
    wscript.Echo "    /sidcol        = Include a column with the SID in the reporting file."
    wscript.Echo "    /nousercol     = Do not include a column with user name."
    wscript.Echo "    /nocomputercol = Do not include a column with the computer name."
    wscript.Echo "    /nosourcecol   = Do not include a column with the event source."
    wscript.Echo "    /notaskcol     = Do not include a column with event task category."
    wscript.Echo "    /forcemta      = Archive for all logs will be forced when using /allevents."
    wscript.Echo ""
    wscript.Echo " Examples:"
    wscript.Echo "    cscript " & wscript.ScriptName & " " & Chr(34) & "Directory Service" & Chr(34) & " MyFile.TXT /notable"
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " /allevents /csv /txt"
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " System /txt /nostats"
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " /allwmi /evtx /days=20"
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " /allwmi /xml " & Chr(34) & "/except:security,application" & Chr(34)
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " Microsoft-Windows-UAC/Operational /channel /csv"
    wscript.Echo ""
    wscript.Echo "    cscript " & wscript.ScriptName & " Application /channel /query:*[System[(Level=2)]] /csv"
End Sub

Class ezPLA
    '************************************************
    'ezPLA VB Class
    'Version 1.0.1
    'Date: 4-24-2009
    'Author: Andre Teixeira - andret@microsoft.com
    '************************************************
    
    Private objFSO 
    Private objShell
    
    Public Section
    Public SectionPriority
    Public AlertType
    Public AlertPriority
    Public Symptom
    Public Details
    Public MoreInformation
    
    Private ALERT_INFORMATION
    Private ALERT_WARNING
    Private ALERT_ERROR
    Private ALERT_NOTE
    
    Public Function AddAlerttoPLA()
        
        Set objShell = CreateObject("WScript.Shell")
        Set objFSO = CreateObject("Scripting.FileSystemObject")
            
        ALERT_INFORMATION = 1
        ALERT_WARNING = 2
        ALERT_ERROR = 3
        ALERT_NOTE = 4
                
        On Error Resume Next
        
        'Validation
        
        If Len(Section) = 0 Then
            Section = "Messages"
        End If
        
        If Len(SectionPriority) = 0 Then
            If IsNumeric(SectionPriority) Then
                SectionPriority = CInt(SectionPriority)
            Else
                SectionPriority = 50 'Default Value
            End If
            SectionPriority = 50 'Default Value
        End If
    
        If Not IsNumeric(AlertType) Then
            AlertType = ALERT_NOTE
        ElseIf AlertType > 4 Then
            AlertType = ALERT_NOTE
        End If
        
        If Not IsNumeric(AlertPriority) Then
            AlertPriority = 20 - AlertType
        End If
        
        If Len(Symptom) = 0 Then
            DisplayError "Checking Values for Symptom", 5000, "AddAlertoPLA", "You have to assign a correct value for Symptom."
            Exit Function
        End If
    
        WriteAlertToPLA
        
    End Function
    
    Private Function WriteAlertToPLA()
        
        Dim strAlertType
        Dim XMLDoc
        Dim XMLDoc2
        
        Dim objSectionElement
        Dim objTableElement
        Dim objXMLAtt
        Dim objReportElement
        Dim objHeaderElement
        Dim objItemElement
        Dim objDataElement
        Dim strDiagnosticXMLPath
                
        strDiagnosticXMLPath = "..\ReportFiles\Diagnostic_Results.XML"
        
        Select Case AlertType
            Case ALERT_INFORMATION
                strAlertType = "info"
            Case ALERT_WARNING
                strAlertType = "warning"
            Case ALERT_ERROR
                strAlertType = "error"
            Case ALERT_NOTE
                strAlertType = "note"
        End Select
        
        Set XMLDoc = CreateObject("Microsoft.XMLDOM")
        XMLDoc.async = "false"
    
        If objFSO.FileExists(strDiagnosticXMLPath) Then 'A PLA reporting already exists
            XMLDoc.Load strDiagnosticXMLPath
            Set objSectionElement = XMLDoc.selectNodes("/Report/Section[@name='" & Section & "']").Item(0) 'Try to find the 'Section' section
            If CheckForError(XMLDoc, "Searching Section Object") <> 0 Then Exit Function
        Else
            wscript.Echo "      " & strDiagnosticXMLPath & " does not exist. Creating it..."
            If Not objFSO.FolderExists("..\ReportFiles") Then objFSO.CreateFolder ("..\ReportFiles")
            XMLDoc.loadXML ("<?xml version=""1.0""?><?xml-stylesheet type=""text/xsl"" href=""report.xsl""?><Report name=""msdtAdvisor"" level=""1"" version=""1"" top=""9999"" portable=""1""/>")
            If CheckForError(XMLDoc, "Loading Standard XML file") <> 0 Then Exit Function
        End If
              
        If XMLObjectIsEmptyorNothing(objSectionElement) Then  'Create the 'Messages' section if it does not exist
                Set objReportElement = XMLDoc.selectNodes("/Report").Item(0)
                
                Set objSectionElement = XMLDoc.createElement("Section")
                
                Set objXMLAtt = XMLDoc.createAttribute("name")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = Section
                Set objXMLAtt = XMLDoc.createAttribute("expand")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = "true"
                Set objXMLAtt = XMLDoc.createAttribute("key")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(SectionPriority)
                
                objReportElement.appendChild objSectionElement
                
                If CheckForError(XMLDoc, "Creating Section Object") <> 0 Then Exit Function
        End If
        
        'Setting Alert Type and Priority
        Set objTableElement = XMLDoc.createElement("Table")
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("style")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = "info"
        Set objXMLAtt = XMLDoc.createAttribute("key")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(AlertPriority)
        
        Set objHeaderElement = XMLDoc.createElement("Header")
        objTableElement.appendChild objHeaderElement
        If CheckForError(XMLDoc, "Setting Alert Type and Priority to XML Header") <> 0 Then Exit Function
        
        Set objItemElement = XMLDoc.createElement("Item")
        Set objDataElement = XMLDoc.createElement("Data")
        
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "Symptom"
        Set objXMLAtt = XMLDoc.createAttribute("img")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("message")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "standard_Message"
        
        objDataElement.appendChild XMLDoc.createTextNode(Symptom)
        objItemElement.appendChild objDataElement
    
        If CheckForError(XMLDoc, "Appending Symptom to XML") <> 0 Then Exit Function
    
        If Len(Details) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Details"" message=""standard_Message"">" & Details & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending Details to XML") <> 0 Then Exit Function
        End If
                    
        If Len(MoreInformation) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Additional Information"" message=""standard_Message"">" & MoreInformation & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending MoreInformation to XML") <> 0 Then Exit Function
        End If
        
        objTableElement.appendChild objItemElement
        If CheckForError(XMLDoc, "Appending Table to XML") <> 0 Then Exit Function
        
        objSectionElement.appendChild objTableElement
        If CheckForError(XMLDoc, "Appending Alert XML Element to XML") <> 0 Then Exit Function
        
        XMLDoc.Save strDiagnosticXMLPath
    
        If CheckForError(XMLDoc, "Saving Report.XML file") <> 0 Then Exit Function
    
    End Function
    
    Private Function XMLObjectIsEmptyorNothing(objXML)
        On Error Resume Next
        XMLObjectIsEmptyorNothing = (objXML Is Nothing)
        If Err.Number > 0 Then
            XMLObjectIsEmptyorNothing = IsEmpty(objXML)
        End If
        Err.Clear
    End Function
    
    Private Function TranslateXMLChars(strRAWString)
        strRAWString = Replace(strRAWString, "&", "&amp;")
        strRAWString = Replace(strRAWString, "<", "&lt;")
        strRAWString = Replace(strRAWString, ">", "&gt;")
        strRAWString = Replace(strRAWString, "'", "&apos;")
        strRAWString = Replace(strRAWString, Chr(34), "&quot;")
        TranslateXMLChars = strRAWString
    End Function
    
    Private Function CheckForError(xmlFile, strOperation)
        Dim strErrText
            If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
                If Err.Number <> 0 Then
                    DisplayError strOperation, Err.Number, Err.Source, Err.Description
                    CheckForError = Err.Number
                Else
                    With xmlFile.parseError
                        strErrText = "Failed to process/ load XML file " & _
                                "due the following error:" & vbCrLf & _
                                "Error #: " & .errorCode & ": " & .reason & _
                                "Line #: " & .Line & vbCrLf & _
                                "Line Position: " & .linepos & vbCrLf & _
                                "Position In File: " & .filepos & vbCrLf & _
                                "Source Text: " & .srcText & vbCrLf & _
                                "Document URL: " & .url
                        CheckForError = .errorCode
                    End With
                    DisplayError strOperation, 5001, "CheckForXMLError", strErrText
                End If
            Else
                CheckForError = 0
            End If
    End Function
    
    Private Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
        On Error Resume Next
        If errNumber <> 0 Then
            wscript.Echo "Error " & HexFormat(errNumber) & IIf(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
            wscript.Echo errSource & " - " & errDescription
        Else
            wscript.Echo "An error has ocurred!. " & IIf(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        End If
    End Sub
End Class
