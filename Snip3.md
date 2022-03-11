# _Mitigation based on EDR queries

:radioactive: _EDRs each have different languages, so it is not always easy or possible to find an equivalence to cover the same technique (or sub-technique). An attempt has been made to cover the most significant of the attack that, once implemented in the EDR, will generate an IOA every time the malware/campaign/actor tries to use the same mechanisms_:radioactive:

---

* [TA0002][T1059.005] Detection based on tree execution after potentially dangerous VBS



##### XQL - XDR Palo Alto

```
dataset = xdr_data 
| filter event_type = ENUM.PROCESS
| filter lowercase(causality_actor_process_image_name) in ("wscript.exe","cscript.exe")
and lowercase(actor_process_image_name) in ("cmd.exe","powershell.exe")
and lowercase(action_process_image_name) in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe")
```

##### KQL - ATP Microsoft

```
DeviceProcessEvents
| where InitiatingProcessParentFileName in ("wscript.exe","cscript.exe")
and InitiatingProcessFileName in ("cmd.exe","powershell.exe")
and FileName in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe")
```

##### SQL - Orion Panda Security (Cytomic)

```
select * from ProcessOps where 
ParentFilename in ('cmd.exe','powershell.exe')
and ChildFilename in ('regasm.exe','regsvcs.exe','msbuild.exe','installutil.exe')
and Date >= today()-15
```
<br><br>

* [TA0005][T1055] Detection based on injections over legitimate process related with .NET

##### XQL - XDR Palo Alto

```
dataset = xdr_data 
| filter event_type = ENUM.INJECTION
| filter lowercase(actor_process_command_line) contains "-executionpolicy*remotesigned"
| filter lowercase(action_remote_process_image_name) in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe")
```
<br><br>

 * [TA0003][T1547.001] Persitence over startup folder using scripts


##### XQL - XDR Palo Alto

```
dataset = xdr_data 
| filter event_type = ENUM.FILE and event_sub_type = ENUM.FILE_CREATE_NEW
| filter lowercase(action_file_name) ~= "(.vbs|.bat|.ps1)$"
and lowercase(action_file_path) ~= "\\(appdata|programdata)\\.*\\startup\\"
```
##### KQL - ATP Microsoft

```
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName matches regex "(.vbs|.bat|.ps1)$"
and FolderPath matches regex @"(appdata|programdata)\.*\startup"
```

##### SQL - Orion Panda Security (Cytomic)

```
select * from ProcessOps where 
match(ChildFilename, '(.vbs|.bat|.ps1)$')
and match(ChildPath, '(appdata|programdata)\\.*\\startup')
and Date >= today()-15
```
<br><br>

* [TA0011][T1573] Detection of requests to public IPs by potentially injected legitimate software related with .NET

##### XQL - XDR Palo Alto

```
dataset = xdr_data 
| filter 
(
    lowercase(actor_process_image_name) in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe") or
    lowercase(action_process_image_name) in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe") or 
    lowercase(action_remote_process_image_name) in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe") //Only using this field will be more accurate
)
| alter range1 = incidr(action_remote_ip , "10.0.0.0/8")
| alter range2 = incidr(action_remote_ip , "192.168.0.0/16")
| alter range3 = incidr(action_remote_ip , "172.16.0.0/12")
| filter range1 = false and range2 = false and range3 = false
| fields agent_hostname, action_remote_ip, action_remote_port, causality_actor_process_image_name, causality_actor_process_command_line, actor_process_image_name, actor_process_command_line, action_file_name, action_process_image_command_line, action_remote_process_image_name
```

##### KQL - ATP Microsoft

```
union DeviceProcessEvents, DeviceNetworkEvents
| where 
(
    InitiatingProcessFileName in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe") or FileName in ("regasm.exe","regsvcs.exe","msbuild.exe","installutil.exe")
)
and RemoteIPType == "Public"
```

##### SQL - Orion Panda Security (Cytomic)

```
select * from  -- Use "select distinct(RemoteIp) from" to filter FP
(
    select * from NetworkOps where
    (
        Ipv4Status = 1
        and ParentFilename in ('cmd.exe','powershell.exe')
    )
and Date >= today()-15 
) as NetQuery
join
(
    select * from ProcessOps where
    ChildFilename in ('regasm.exe','regsvcs.exe','msbuild.exe','installutil.exe')
) as ProcQuery on NetQuery.Muid = ProcQuery.Muid
where Date >= today()-15

```

# _Yara

:radioactive:_Rule has been performed on AsyncRAT samples that have usually been used in this campaign/actor with very few changes between them._:radioactive:

---

```
rule Async 
{
	meta:
		description = "AsyncRAT used by some campaigns of Operation layover|TA2541"
		category = "RAT"
		author = "vc0rexor"
		reference = "https://github.com/vc0RExor/Malware-Threat-Reports/blob/main/RAT/Snip3%20loader/Snip3_Aaron_Jornet_EN.pdf"
		date = "2022-03-01"
		hash1 = "42C04F36D21BE3F9ECB755D3884DDDB783B04C7B8DFA94903A0B32AE63BC85F6"
		
	strings:
		$1 = "pastebin" fullword ascii nocase
		$3 = "aes256" fullword ascii nocase
		$31 = "async" nocase
		$33 = "downloadstring" fullword ascii nocase
		$4 = { 5C 00 6E 00 75 00 52 00 5C 00 6E 00 6F 00 69 00 73 00 72 00 65 00 56 00 74 00 6E 00 65 00 72 00 72 00 75 00 43 00 5C 00 73 00 77 00 6F 00 64 00 6E 00 69 00 57 00 5C 00 74 00 66 00 6F 00 73 00 6F 00 72 00 63 00 69 00 4D 00 5C 00 65 00 72 00 61 00 77 00 74 00 66 00 6F 00 53 00 00 03 }
		$5 = { 53 00 65 00 6C 00 65 00 63 00 74 00 20 00 2A 00 20 00 66 00 72 00 6F 00 6D 00 20 00 57 00 69 00 6E 00 33 00 32 00 5F 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6D 00 00 }
		$6 = { 65 00 63 00 68 00 6F 00 20 00 6F 00 66 00 66 00 00 1F 74 00 69 00 6D 00 65 00 6F 00 75 00 74 00 20 00 33 00 20 00 3E 00 20 00 4E 00 55 00 4C 00 00 15 53 00 54 00 41 00 52 00 54 00 20 00 22 00 22 00 20 00 22 00 00 07 43 00 44 00 20 00 00 0B 44 00 45 00 4C 00 20 00 }
	
	condition:
		uint16(0) == 0x5a4d and all of them
}
```

> :t-rex: [vc0=Rexor](https://github.com/vc0RExor) :shield:
