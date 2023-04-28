resource "my_alert_rule" "rule_151" {
  name = "Potential lolbins usage detected DFE"
  log_analytics_workspace_id = var.client_log_analytics_workspace_id
  query_frequency = PT12H
  query_period = PT12H
  severity = Low
  query = <<EOF
DeviceProcessEvents
| where InitiatingProcessFileName  == "cmd.exe"
| project-rename ipfn=InitiatingProcessFileName, ipfp=InitiatingProcessFolderPath, cl=ProcessCommandLine
| where (cl has "AccCheckConsole" and cl has_any ("-window", ".dll")) or (cl has_all ("Adplus", "-pn")) or (cl has "Advpack" and cl has_any ("LaunchINFSection", "RegisterOCX")) or (cl has "AgentExecutor" and cl has_any ("-powershell", ".ps1")) or (cl has "AppInstaller" and cl contains "?source=") or (cl has "Appvlp" and cl has_any (".bat", "powershell")) or (cl has "At" and cl contains "/every") or (cl has_all ("Bash", "-c")) or (cl has "Bginfo" and cl has_any (".bgi", "/popup", "/nolicprompt")) or (cl has_all ("Bitsadmin", "/create")) or (cl has "Cdb" and cl has_any ("-cf", "-pd", "-pn")) or (cl has "CertOC" and (cl contains "-LoadDLL" or cl contains "-GetCACAPS")) or (cl has "CertReq" and cl contains "-Post") or (cl has "CertUtil" and cl has_any ("-urlcache", "-split", "-verifyctl", "-encode", "-decode", "-decodehex")) or (cl has "CL_Invocation.ps1" and cl has "SyncInvoke") or (cl has "CL_LoadAssembly.ps1" and cl contains ".dll") or (cl has "CL_Mutexverifiers.ps1" and cl contains "runAfterCancelProcess") or (cl has "Cmdkey" and cl contains "/list") or (cl has "Cmdl32" and cl has_any ("/vpn", "/lan")) or (cl has "Cmstp" and cl has_all ("/ni", "/s")) or (cl has_all ("Comsvcs", "MiniDump")) or (cl has "Cmstp" and cl has_all ("/ni", "/s")) or (cl has "Coregen" and cl has_any (".dll", "-L", "-l")) or (cl has "csc" and (cl contains "-out" or cl contains "-target")) or (cl has "Desk" and cl has_all (".scr", "InstallScreenSaver")) or (cl has_all ("Desktopimgdownldr", "/lockscreenurl")) or (cl has_all ("Dfshim.dll", "ShOpenVerbApplication")) or (cl has "Dotnet" and cl has_any (".dll", "msbuild")) or (cl has_all ("Dxcap", "-c")) or (cl has "esentutl" and cl has_any ("/y", "//vss")) or (cl has_all ("fltMC", "unload")) or (cl has_all ("forfiles", "/p", "/m", "/c")) or (cl has_all ("ftp", "-s:")) or (cl has "GfxDownloadWrapper" and cl !has "gameplayapi.intel.com") or (cl has "Gpscript" and cl has_any ("/logon", "/startup")) or (cl has_all ("ie4uinit", "-BaseSettings")) or (cl has "Ieadvpack" and cl has_any ("LaunchINFSection", "RegisterOCX")) or (cl has_all ("Ieframe", "OpenURL")) or (cl has "iLasm" and cl has_any ("//exe", "//dll")) or (cl has_all ("Installutil", "/U")) or (cl has "jsc" and cl has_any ("LaunchForDeploy", "LaunchForDebug")) or (cl has "Manage-bde.wsf" and cl has_any ("comspec", ".exe")) or (cl has_all ("mavinject", "/INJECTRUNNING")) or (cl has "Mftrace" and cl has_any ("cmd", "powershell")) or (cl has "Microsoft.Workflow.Compiler") or (cl has "MpCmdRun" and cl has_any ("/DownloadFile", "/url", "/path", "-DownloadFile", "-url", "-path")) or (cl has "Msdeploy" and cl has_any (".bat", "RunCommand")) or (cl has_all ("Mshtml", "PrintHTML")) or (cl has "Msiexec" and cl has_any ("://", ".dll")) or (cl has_all("netsh", "add helper")) or (cl has "Ntdsutil" and cl has_all ("ntds", "create full")) or (cl has "Odbcconf" and cl has_any (".rsp", "-f", "/a", ".dll")) or (cl has "OneDriveStandaloneUpdater") or (cl has ("Pcalua") and cl has_any ("-a", ".dll", ".cpl")) or (cl has_all("Pcwrun", ".exe")) or (cl has_all("Pcwutl", "LaunchApplication")) or (cl has "Pktmon" and cl has_any ("start", "filter")) or (cl has "Pnputil" and cl has_any ("-i", "-a")) or (cl has "Powerpnt" and cl has_any ("http", ".dll")) or (cl has "Print" and cl has_all ("/D", ".exe")) or (cl has "PrintBrm" and cl has_any ("-b", "-d", "-f", "-r")) or (cl has "Psr" and cl has_all ("/gui", "0")) or (cl has "Pubprn.vbs" and cl has_any ("script", ".sct")) or (cl has "Rasautou" and cl has_any ("-d", "-p")) or (cl has "rdrleakdiag" and cl has_all ("/p", "/o", "/fullmemdmp")) or ((cl has "Reg" and cl has_all ("export", ".reg")) or (cl has_all ("Reg", "save"))) or (cl has "Regasm" and cl has_any (".dll", "/U")) or (cl has "Regedit" and cl has_any (".reg", "/E")) or (cl has_all ("Register-cimprovider", ".dll")) or (cl has_all ("Regsvcs", ".dll")) or (cl has "Regsvr32" and cl has_all ("/s", ".sct", ".dll")) or (cl has_all("Remote.exe", "/s")) or (cl has "Replace" and cl has_any ("\\\\", "/a")) or (cl has "Rpcping" and cl has_all ("-s", "-e", "-a", "-u") or cl has_all ("/s", "/e", "/a", "/u")) or (cl has "Rundll32" and cl has_any ("\\\\", "javascript", "powershell", ":")) or (cl has_all("Runscripthelper", "surfacecheck")) or (cl has "Sc" and cl has_any ("create", "config")) or (cl has_all ("Schtasks", "create")) or (cl has_all ("Scriptrunner", "create")) or (cl has "SettingSyncHost" and cl has_any ("-LoadAndRunDiagScript", "-LoadAndRunDiagScriptNoCab")) or (cl has_all ("Setupapi", "InstallHinfSection")) or (cl has_all ("Shdocvw", "OpenURL")) or (cl has "Shell32" and cl has_any ("Control_RunDLL", "ShellExec_RunDLL")) or (cl has_all ("Sqlps", "-noprofile")) or (cl has "SqlToolsPs" and cl has_all ("-noprofile", "-command")) or (cl has "Squirrel" and cl has_any ("--download", "--update", "--updateRollback")) or (cl has_all ("Syssetup", "SetupInfObjectInstallAction")) or (cl has_all("Te", ".wsc")) or (cl has "Tracker" and cl has_all ("/d", "/c", ".dll")) or (cl has "Ttdinject" and cl has_all ("/ClientParams", "/Launch")) or (cl has "Update" and cl has_any ("--download", "--update", "--updateRollback", "--processStart")) or (cl has "Url" and cl has_any ("OpenURL", "FileProtocolHandler")) or (cl has_all ("UtilityFunctions.ps1", ".dll")) or (cl has "Vbc" and cl has_any ("/target", ".dll")) or (cl has "Verclsid" and cl has_all ("/S", "/C")) or (cl has "VisualUiaVerifyNative") or (cl has "Vsiisexelauncher" and cl has_all ("-p", "-a")) or (cl has_all ("Wfc", ".xoml")) or (cl has "Winrm.vbs" and cl has_any ("invoke Create", "get wmicimv2", "-format")) or (cl has "Winword" and cl has_any ("http", ".dll")) or (cl has "Wlrmdr" and cl has_all ("-s", "-f", "-t", "-m", "-a", "-u")) or (cl has "mmc" and cl !has "windows\\system32") or (cl has "Wmic" and cl has_any ("call create", "get brief")) or (cl has "Wsl" and cl has_any ("-e", "-u", "--exec", "-c")) or (cl has "Xwizard" and cl has_any ("RunWizard", "/taero", "/u")) or (cl has_all ("Zipfldr", "RouteTheCall")) or (ipfn has "conhost" and not (cl has_any ("werfault.exe", "conhost", "csc", "cvtres", "ccm", "mofcomp.exe", "DeviceCensus.exe", "SecEdit.exe", "ngen.exe", "CompatTelRunner.exe", "find.exe", "sc.exe", "mscorsvw.exe", "ipstats", "tcpstats", "udpstats", "Remediation_Script.ps1", "fstmp")) and not (FileName has_any ("Dropbox.exe", "7za.exe", "RdrCEF.exe", "GoogleUpdate.exe", "hostname.exe", "chcp.com")) and not(cl contains "JABQAHIAbwBnAHIAZQBzAHMAUAByAGUAZgBlAHIAZQBuAG")) or (ipfn has "cscript" and cl matches regex "[.]\\w\\w\\w[:]") or (ipfn has_any ("fsi.exe", "csi.exe", "rcsi.exe") and not (ipfp has_any ("Visual Studio", "Microsoft Web Tools"))) or (cl has_any ("Aspnet_Compiler", "AtBroker", "ConfigSecurityPolicy", "control", "DataSvcUtil", "DefaultPack", "diantz", "diskshadow", "dnscmd", "Dnx", "Dump64", "eventvwr", "expand", "extexport", "extrac32", "Fsi", "Fsianycpu", "hh", "ieexec", "IMEWDBLD", "infdefaultinstall", "makecab", "Microsoft.Workflow.Compiler", "Msconfig", "Msdt", "Mshta", "Msxsl", "OfflineScannerShell", "OneDriveStandaloneUpdater", "Pester.bat", "Presentationhost", "Procdump", "Rcsi", "Regini", "Runonce", "Sqldumper", "Stordiag", "Syncappvpublishingserver", "Tttracer", "Vsjitdebugger", "Wab", "Workfolders", "Wscript", "Wsreset"))
| project TimeGenerated, HostCustomEntity=DeviceName, AccountCustomEntity = AccountName, CommandLine = cl, ParentProcess = ipfn, GrandParentProcess = InitiatingProcessParentFileName, ParentCommand=InitiatingProcessCommandLine
EOF
  entity_mapping {
    entity_type = Account
    field_mappings {
      identifier = FullName
      column_name = AccountCustomEntity
    }
    entity_type = Host
    field_mappings {
      identifier = FullName
      column_name = HostCustomEntity
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = CommandLine
    }
    entity_type = File
    field_mappings {
      identifier = Name
      column_name = GrandParentProcess
    }
    entity_type = Process
    field_mappings {
      identifier = CommandLine
      column_name = ParentCommand
    }
  }
  tactics = ['CommandAndControl']
  techniques = ['T1105']
  display_name = Potential lolbins usage detected (DFE)
  description = <<EOT
'Living off the land binaries are microsoft signed executables that are not detected by antivirus solutions but offer different opportunities
to enumerate the machine and launch attacks. This alert in particular detects the use of these binaries at the process level and alerts when they are used. Ref: https://lolbas-project.github.io
EOT
  enabled = True
  create_incident = True
  grouping_configuration {
    enabled = False
    reopen_closed_incident = False
    lookback_duration = PT5H
    entity_matching_method = AllEntities
    group_by_entities = []
    group_by_alert_details = []
    group_by_custom_details = []
  }
  suppression_duration = PT5H
  suppression_enabled = False
  event_grouping = {'aggregationKind': 'SingleAlert'}
}
