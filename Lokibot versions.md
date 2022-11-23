# _Mitigation based on EDR queries

:radioactive: _EDRs each have different languages, so it is not always easy or possible to find an equivalence to cover the same technique (or sub-technique). An attempt has been made to cover the most significant of the attack that, once implemented in the EDR, will generate an IOA every time the malware/campaign/actor tries to use the same mechanisms_:radioactive:

---

# _ Oportunity of detection

Considering that mitigation can be performed from different technologies, the elements that should be taken into account to perform a proper detection of the following versions of Lokibot could be these:

* Eqnedt32.exe launching external requests
```
(Prc) Eqnedt32.exe > Public RemoteIP
``` 

* Eqnedt32.exe launching processes in unusual folders (Temp/Public/ProgramData)
```
(Prc) Eqnedt.exe > (ChildPath)  Temp/Public/ProgramData > (ChildPrc) <Random>.exe
```

* Process Hollowing type injections in processes that being in unusual folders are injected to a process launched by itself with the same name
```
(Prc) <Random>.exe > (PrcPath)  Temp/Public/ProgramData > (ChildPath)  Temp/Public/ProgramData > (ChildInjectPrc) <SameRandom>.exe
```

* Process Hollowing in .NET-related processes
```
(Prc) <Random>.exe > (PrcPath)  Temp/Public/ProgramData > (ChildInjectPrc) applaunch.exe | installutil.exe | regsvcs.exe | msbuild.exe | regasm.exe | aspnet_compiler.exe
OR
(Prc) powershell.exe > (ChildInjectPrc) applaunch.exe | installutil.exe | regsvcs.exe | msbuild.exe | regasm.exe | aspnet_compiler.exe
```

* Executions from an unknown binary launching other binaries in unusual folders
```
(Prc) <Random>.exe > (PrcPath)  Temp/Public/ProgramData > (ChildPath)  Temp/Public/ProgramData > (ChildPrc) <SameRandom>.exe
```

* Concatenated executions of obfuscated scripts 
```
(GrandParentPrc) Powershell.exe | cmd.exe | wscript.exe | cscript.exe  > (Prc) Powershell.exe | cmd.exe  > (ChildInjectPrc) applaunch.exe | installutil.exe | regsvcs.exe | msbuild.exe | regasm.exe | aspnet_compiler.exe
```

* From an injected .NET SW to make network requests
```
(ChildInjectPrc) applaunch.exe | installutil.exe | regsvcs.exe | msbuild.exe | regasm.exe | aspnet_compiler.exe > Public RemoteIP
```

* From a process that has been injected by another process with the same name, sensitive data is being accessed via files or application logs such as FTP/Mail/SSH/Browsers.
```
(InjectPrc) applaunch.exe | installutil.exe | regsvcs.exe | msbuild.exe | regasm.exe | aspnet_compiler.exe > (ChildPath) Mail/FTP/Browser/PSW manager paths
```

---

# _EDR Proposed Rules

The following rules have been tested in a Cortex environment where several machines have been infected with different versions of Lokibot to try to understand all the possible behaviours of this malware and how the EDR interprets it. Subsequently, we have translated to Microsoft ATP the query language that could best fit similar queries. 

All recommendations, complaints and hate, are welcome to continue improving the content, thank you :) <3

<br/><br/>

* [TA0002][T1059.001] Detection by concatenated script execution tree

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.PROCESS
and causality_actor_process_image_name in ("wscript.exe","cscript.exe")
and actor_process_image_name in ("powershell.exe","cmd.exe")
and action_process_image_name in ("powershell.exe","cmd.exe")
```
> Same, but more accurate

```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.PROCESS
and causality_actor_process_image_name in ("wscript.exe","cscript.exe")
and 
(
    actor_process_image_name in ("powershell.exe","cmd.exe") and
    actor_process_command_line contains "*::frombase64string(*.replace(*-windowstyle*hidden*"
)
and
(
    action_process_image_name in ("powershell.exe","cmd.exe") and
    action_process_image_command_line contains "*.downloadstring(*.load(*.invoke*"
)
| fields agent_hostname, event_type, event_sub_type, causality_actor_process_image_name, actor_process_image_name, actor_process_command_line, action_process_image_name, action_process_image_command_line, action_file_name
```

##### KQL - Microsoft ATP
```
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("wscript.exe","cscript.exe") //in~ added added by navajanegra's post talk recommendation - THANKS!
and InitiatingProcessFileName in~ ("powershell.exe","cmd.exe")
and FileName in~ ("powershell.exe","cmd.exe")
```
> Same, but more accurate
```
DeviceProcessEvents
| where InitiatingProcessParentFileName in~ ("wscript.exe","cscript.exe") //in~ added added by navajanegra's post talk recommendation - THANKS!
and 
(
    InitiatingProcessFileName in~ ("powershell.exe","cmd.exe") and
    InitiatingProcessCommandLine has_all ("::frombase64string(",".replace(","-windowstyle","hidden")
)
and 
(
    FileName in~ ("powershell.exe","cmd.exe") and 
    ProcessCommandLine has_all (".downloadstring(",".load(",".invoke")
)
```
<br/><br/>
* [TA0010][T1041] Requests to external IPs from potentially injected .NET processes

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter action_remote_process_image_name in ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
| alter range1 = incidr(action_remote_ip , "10.0.0.0/8")
| alter range2 = incidr(action_remote_ip , "192.168.0.0/16")
| alter range3 = incidr(action_remote_ip , "172.16.0.0/12")
| filter range1 = false and range2 = false and range3 = false
| fields agent_hostname, action_remote_process_image_name, action_remote_ip 
```

##### KQL - Microsoft ATP
```
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
and RemoteIPType == "Public"
```

<br/><br/>

* [TA0002][T1203] Exploitation of microsoft equation for file downloads

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.NETWORK
and 
(
    causality_actor_process_image_name in ("eqnedt32.exe") or 
    actor_process_image_name in ("eqnedt32.exe")
)
| alter range1 = incidr(action_remote_ip , "10.0.0.0/8")
| alter range2 = incidr(action_remote_ip , "192.168.0.0/16")
| alter range3 = incidr(action_remote_ip , "172.16.0.0/12")
| filter range1 = false and range2 = false and range3 = false
```

##### KQL - Microsoft ATP
```
DeviceNetworkEvents
| where 
(
    InitiatingProcessParentFileName in~ ("eqnedt32.exe") or 
    InitiatingProcessFileName in~ ("eqnedt32.exe")
)
and RemoteIPType == "Public" 
```

<br/><br/>

* [TA0002][T1203] Process tree after eqnedt exploitation

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type in (ENUM.PROCESS,ENUM.INJECTION) 
and causality_actor_process_image_name in ("eqnedt32.exe")
and 
(
    actor_process_image_name = action_process_image_name or
    actor_process_image_name = action_remote_process_image_name
)
and actor_process_command_line contains "\public\"
```

##### KQL - Microsoft ATP
```
union DeviceProcessEvents, DeviceEvents
| where InitiatingProcessParentFileName in~ ("eqnedt32.exe")
and InitiatingProcessFileName == FileName 
and InitiatingProcessCommandLine contains @"\Public\"
```

<br/><br/>

*  [TA0005][T1055.012] Injection into .NET processes

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.INJECTION and event_sub_type in (ENUM.INJECTION_PROCESS_HOLLOW, ENUM.INJECTION_SET_THREAD_CONTEXT)
and action_remote_process_image_name in ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
```

##### KQL - Microsoft ATP
```
DeviceEvents
| where ActionType in~ ("CreateRemoteThreadApiCall","NtAllocateVirtualMemoryApiCall","NtMapViewOfSectionRemoteApiCall","SetThreadContextRemoteApiCall","WriteProcessMemoryApiCall")
and FileName in~ ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
```
<br/><br/>

*  [TA0005][T1055.012] Injection into processes launched by the same binary

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.INJECTION and event_sub_type in (ENUM.INJECTION_PROCESS_HOLLOW, ENUM.INJECTION_SET_THREAD_CONTEXT)
and actor_process_image_name = action_remote_process_image_name
| comp count(actor_process_image_name) by actor_process_image_name, action_remote_process_image_name
```

##### KQL - Microsoft ATP
```
DeviceEvents
| where ActionType in~ ("CreateRemoteThreadApiCall","NtAllocateVirtualMemoryApiCall","NtMapViewOfSectionRemoteApiCall","SetThreadContextRemoteApiCall","WriteProcessMemoryApiCall")
and InitiatingProcessFileName == FileName
| summarize count() by InitiatingProcessFileName, FileName
```

<br/><br/>

* [TA0010][T1041] Requests from an injected process to public ip

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter actor_process_image_name = action_remote_process_image_name
| alter range1 = incidr(action_remote_ip , "10.0.0.0/8")
| alter range2 = incidr(action_remote_ip , "192.168.0.0/16")
| alter range3 = incidr(action_remote_ip , "172.16.0.0/12")
| filter range1 = false and range2 = false and range3 = false
| fields agent_hostname, action_remote_process_image_name, action_remote_ip 
```

##### KQL - Microsoft ATP
```
DeviceEvents
| where ActionType in~ ("CreateRemoteThreadApiCall","NtAllocateVirtualMemoryApiCall","SetThreadContextRemoteApiCall","WriteProcessMemoryApiCall")
and InitiatingProcessFileName == FileName
and isnotempty(InitiatingProcessFileName)
| join 
(
    DeviceNetworkEvents
    | where RemoteIPType == "Public"
    and isnotempty(RemoteIP)
) on DeviceName
| summarize count() by ActionType, InitiatingProcessFileName, FileName, RemoteIPType, RemoteIP1
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","vmtoolsd.exe","rundll32.exe") //Cut known processes, here should be a suspicious process in a temporary folder
```

# _Experimental Queries

This space is for less refined/tested queries where I have gone looking for very specific elements of a particular event

<br/><br/>

* [TA0010][T1041] Requests to external IPs from potentially injected .NET processes

##### XQL - Cortex XDR Palo Alto
```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.INJECTION and event_sub_type in (ENUM.INJECTION_CREATE_REMOTE_THREAD, ENUM.INJECTION_PROCESS_HOLLOW, ENUM.INJECTION_SET_THREAD_CONTEXT)
and action_remote_process_image_name in ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
| fields agent_hostname, action_remote_process_image_name
| join
(
    dataset = xdr_data
    | filter event_type = ENUM.NETWORK
    | alter range1 = incidr(action_remote_ip , "10.0.0.0/8")
    | alter range2 = incidr(action_remote_ip , "192.168.0.0/16")
    | alter range3 = incidr(action_remote_ip , "172.16.0.0/12")
    | filter range1 = false and range2 = false and range3 = false
    | fields agent_hostname, action_remote_process_image_name, action_remote_ip 
) as host agent_hostname = host.agent_hostname
```

##### KQL - Microsoft ATP
```
DeviceNetworkEvents
| where RemoteIPType == "Public" 
| join 
(
    DeviceEvents
    | where ActionType in~ ("CreateRemoteThreadApiCall","NtAllocateVirtualMemoryApiCall","NtMapViewOfSectionRemoteApiCall","SetThreadContextRemoteApiCall","WriteProcessMemoryApiCall")
    and FileName in~ ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
) on DeviceName
```

<br/><br/>

* [TA0009][T1005] Access to registers or files from potentially injected processes

##### XQL - Cortex XDR Palo Alto

> Based on Payload in .NET injected version

```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type = ENUM.INJECTION and event_sub_type in (ENUM.INJECTION_CREATE_REMOTE_THREAD, ENUM.INJECTION_PROCESS_HOLLOW, ENUM.INJECTION_SET_THREAD_CONTEXT)
and action_remote_process_image_name in ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
| fields agent_hostname, action_remote_process_image_name
| join
(
    dataset = xdr_data
    | filter event_type in (ENUM.FILE,ENUM.REGISTRY)
    and 
    (
        action_file_path contains "\web data" or 
        action_file_path contains "\login data" or
        action_file_path contains "\netgate\" or 
        action_file_path contains "\lunascape\" or
        action_file_path contains "\mozilla\firefox\" or 
        action_file_path contains "\local\qupzilla\" or
        action_file_path contains "\.purple\accounts" or
        action_file_path contains "\myftp\" or 
        action_file_path contains "\ftpbox\" or
        action_file_path contains "\nexusfile\" or
        action_file_path contains "\netsarang\xftp\" or 
        action_file_path contains "\sherrod ftp\" or 
        action_file_path contains "\sftpnetdrive" or 
        action_file_path contains "\ftp now\sites" or 
        action_file_path contains "\easyftp\" or
        action_file_path contains "\ableftp*\" or 
        action_file_path contains "\jasftp*\" or
        action_file_path contains "\automize*\" or 
        action_file_path contains "\ftpinfo\" or
        action_file_path contains "\cyberduck" or 
        action_file_path contains "\blazeftp\" or
        action_file_path contains "\staff-ftp\sites" or 
        action_file_path contains "\deluxeftp\sites" or 
        action_file_path contains "\alftp\" or
        action_file_path contains "\goftp\" or
        action_file_path contains "\filezilla\" or
        action_file_path contains "\ftpgetter\" or
        action_file_path contains "\flashfxp" or
        action_file_path contains "\novaftp\" or
        action_file_path contains "\smartftp" or
        action_file_path contains "\netdrive\" or
        action_file_path contains "\bitkinex\" or
        action_file_path contains "\foxmail\" or 
        action_file_path contains "\winftp\" or 
        action_file_path contains "\pocomail\" or
        action_file_path contains "\opera mail\" or
        action_file_path ~= "(\.xml|\.cfg|\.dat)$" or
        action_registry_key_name contains "\currentversion\internet settings" or
        action_registry_key_name contains "\vandyke\securefx" or
        action_registry_key_name contains "\martin prikryl" or
        action_registry_key_name ~= "(sessions|accounts)$"
    )
    | fields agent_hostname, action_remote_process_image_name, action_remote_ip 
) as host agent_hostname = host.agent_hostname
```

> Based on Payload injection in a process with the same name than the launcher

```
config case_sensitive = false |
dataset = xdr_data 
| filter event_type in (ENUM.INJECTION) 
and actor_process_image_name = action_remote_process_image_name
| fields agent_hostname, action_remote_process_image_name
| join
(
    dataset = xdr_data
    | filter event_type in (ENUM.FILE,ENUM.REGISTRY)
    and 
    (
        action_file_path contains "\web data" or 
        action_file_path contains "\login data" or
        action_file_path contains "\netgate\" or 
        action_file_path contains "\lunascape\" or
        action_file_path contains "\mozilla\firefox\" or 
        action_file_path contains "\local\qupzilla\" or
        action_file_path contains "\.purple\accounts" or
        action_file_path contains "\myftp\" or 
        action_file_path contains "\ftpbox\" or
        action_file_path contains "\nexusfile\" or
        action_file_path contains "\netsarang\xftp\" or 
        action_file_path contains "\sherrod ftp\" or 
        action_file_path contains "\sftpnetdrive" or 
        action_file_path contains "\ftp now\sites" or 
        action_file_path contains "\easyftp\" or
        action_file_path contains "\ableftp*\" or 
        action_file_path contains "\jasftp*\" or
        action_file_path contains "\automize*\" or 
        action_file_path contains "\ftpinfo\" or
        action_file_path contains "\cyberduck" or 
        action_file_path contains "\blazeftp\" or
        action_file_path contains "\staff-ftp\sites" or 
        action_file_path contains "\deluxeftp\sites" or 
        action_file_path contains "\alftp\" or
        action_file_path contains "\goftp\" or
        action_file_path contains "\filezilla\" or
        action_file_path contains "\ftpgetter\" or
        action_file_path contains "\flashfxp" or
        action_file_path contains "\novaftp\" or
        action_file_path contains "\smartftp" or
        action_file_path contains "\netdrive\" or
        action_file_path contains "\bitkinex\" or
        action_file_path contains "\foxmail\" or 
        action_file_path contains "\winftp\" or 
        action_file_path contains "\pocomail\" or
        action_file_path contains "\opera mail\" or
        //action_file_path ~= "(\.xml|\.cfg|\.dat)$" or
        action_registry_key_name contains "\currentversion\internet settings" or
        action_registry_key_name contains "\vandyke\securefx" or
        action_registry_key_name contains "\martin prikryl" or
        action_registry_key_name ~= "(sessions|accounts)$"
    )
    | fields agent_hostname, event_type, action_remote_process_image_name, action_file_path, action_registry_key_name
) as host agent_hostname = host.agent_hostname
```

##### KQL - Microsoft ATP

> This is not the exact translation, there are certain Cortex fields that do not exist in ATP :(
> > Based on Payload in .NET injected version

```
union DeviceFileEvents, DeviceRegistryEvents, DeviceEvents
| where 
(
    FileName in~ ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe") or
    InitiatingProcessFileName in~ ("applaunch.exe","installutil.exe","regsvcs.exe","msbuild.exe","regasm.exe","aspnet_compiler.exe")
)
and 
(
    FolderPath contains @"\web data" or 
    FolderPath contains @"\login data" or
    FolderPath contains @"\netgate\" or 
    FolderPath contains @"\lunascape\" or
    FolderPath contains @"\mozilla\firefox\" or 
    FolderPath contains @"\local\qupzilla\" or
    FolderPath contains @"\.purple\accounts" or
    FolderPath contains @"\myftp\" or 
    FolderPath contains @"\ftpbox\" or
    FolderPath contains @"\nexusfile\" or
    FolderPath contains @"\netsarang\xftp\" or 
    FolderPath contains @"\sherrod ftp\" or 
    FolderPath contains @"\sftpnetdrive" or 
    FolderPath contains @"\ftp now\sites" or 
    FolderPath contains @"\easyftp\" or
    FolderPath contains @"\ableftp" or 
    FolderPath contains @"\jasftp" or
    FolderPath contains @"\automize" or 
    FolderPath contains @"\ftpinfo\" or
    FolderPath contains @"\cyberduck" or 
    FolderPath contains @"\blazeftp\" or
    FolderPath contains @"\staff-ftp\sites" or 
    FolderPath contains @"\deluxeftp\sites" or 
    FolderPath contains @"\alftp\" or
    FolderPath contains @"\goftp\" or
    FolderPath contains @"\filezilla\" or
    FolderPath contains @"\ftpgetter\" or
    FolderPath contains @"\flashfxp" or
    FolderPath contains @"\novaftp\" or
    FolderPath contains @"\smartftp" or
    FolderPath contains @"\netdrive\" or
    FolderPath contains @"\bitkinex\" or
    FolderPath contains @"\foxmail\" or 
    FolderPath contains @"\winftp\" or 
    FolderPath contains @"\pocomail\" or
    FolderPath contains @"\opera mail\" or 
    //FolderPath matches regex @"(\.xml|\.cfg|\.dat)$" or
    RegistryKey contains @"\currentversion\internet settings" or 
    RegistryKey contains @"\vandyke\securefx" or
    RegistryKey contains @"\martin prikryl" or
    RegistryKey matches regex "(sessions|accounts)$"
)
```

> This is not the exact translation, there are certain Cortex fields that do not exist in ATP :(
> > Based on Payload injection in a process with the same name than the launcher

```
union DeviceFileEvents, DeviceRegistryEvents, DeviceEvents
| where InitiatingProcessFileName == FileName
and 
(
    FolderPath contains @"\web data" or 
    FolderPath contains @"\login data" or
    FolderPath contains @"\netgate\" or 
    FolderPath contains @"\lunascape\" or
    FolderPath contains @"\mozilla\firefox\" or 
    FolderPath contains @"\local\qupzilla\" or
    FolderPath contains @"\.purple\accounts" or
    FolderPath contains @"\myftp\" or 
    FolderPath contains @"\ftpbox\" or
    FolderPath contains @"\nexusfile\" or
    FolderPath contains @"\netsarang\xftp\" or 
    FolderPath contains @"\sherrod ftp\" or 
    FolderPath contains @"\sftpnetdrive" or 
    FolderPath contains @"\ftp now\sites" or 
    FolderPath contains @"\easyftp\" or
    FolderPath contains @"\ableftp" or 
    FolderPath contains @"\jasftp" or
    FolderPath contains @"\automize" or 
    FolderPath contains @"\ftpinfo\" or
    FolderPath contains @"\cyberduck" or 
    FolderPath contains @"\blazeftp\" or
    FolderPath contains @"\staff-ftp\sites" or 
    FolderPath contains @"\deluxeftp\sites" or 
    FolderPath contains @"\alftp\" or
    FolderPath contains @"\goftp\" or
    FolderPath contains @"\filezilla\" or
    FolderPath contains @"\ftpgetter\" or
    FolderPath contains @"\flashfxp" or
    FolderPath contains @"\novaftp\" or
    FolderPath contains @"\smartftp" or
    FolderPath contains @"\netdrive\" or
    FolderPath contains @"\bitkinex\" or
    FolderPath contains @"\foxmail\" or 
    FolderPath contains @"\winftp\" or 
    FolderPath contains @"\pocomail\" or
    FolderPath contains @"\opera mail\" or 
    FolderPath matches regex @"(\.xml|\.cfg|\.dat)$" or
    RegistryKey contains @"\currentversion\internet settings" or 
    RegistryKey contains @"\vandyke\securefx" or
    RegistryKey contains @"\martin prikryl" or
    RegistryKey matches regex "(sessions|accounts)$"
)
```

Thanks for reading and happy hunting, hope it helps :)

> :t-rex: [vc0=Rexor](https://github.com/vc0RExor) :shield:

