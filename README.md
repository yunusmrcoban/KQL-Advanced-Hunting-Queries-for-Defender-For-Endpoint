# KQL-Advanced-Hunting-Queries-for-Defender-For-Endpoint

Malicious 3CX Applications (via network activities)
```
//author:yunusmrcoban
DeviceNetworkEvents
| where InitiatingProcessFileName has '3CXDesktopApp.exe'
| where RemoteUrl in~ ('akamaicontainer.com',
'akamaitechcloudservices.com',
'azuredeploystore.com',
'azureonlinecloud.com',
'azureonlinestorage.com',
'dunamistrd.com',
'glcloudservice.com',
'journalide.org',
'msedgepackageinfo.com',
'msstorageazure.com',
'msstorageboxes.com',
'officeaddons.com',
'officestoragebox.com',
'pbxcloudeservices.com',
'pbxphonenetwork.com',
'pbxsources.com',
'qwepoi123098.com',
'sbmsa.wiki',
'sourceslabs.com',
'visualstudiofactory.com',
'zacharryblogs.com')
| where Timestamp > ago(30d)
//ref:https://github.com/SigmaHQ/sigma/pull/4151/files
```
Malicious 3CX Applications Process (via Hash)
```
//author:yunusmrcoban
DeviceProcessEvents 
| where (ProcessVersionInfoOriginalFileName =~ @'3CXDesktopApp.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'3CXDesktopApp.exe' 
or FolderPath endswith @'\3CXDesktopApp.exe')
| where ProcessVersionInfoProductVersion contains @'18.12.407' or ProcessVersionInfoProductVersion contains @'18.12.416'
or InitiatingProcessVersionInfoProductVersion contains @'18.12.407' or InitiatingProcessVersionInfoProductVersion contains @'18.12.416'
| where InitiatingProcessSHA256 in~ ('DDE03348075512796241389DFEA5560C20A3D2A2EAC95C894E7BBED5E85A0ACC',
'FAD482DED2E25CE9E1DD3D3ECC3227AF714BDFBBDE04347DBC1B21D6A3670405',
'AA124A4B4DF12B34E74EE7F6C683B2EBEC4CE9A8EDCF9BE345823B4FDCF5D868',
'59E1EDF4D82FAE4978E97512B0331B7EB21DD4B838B850BA46794D9C7A2C0983',
'6285FFB5F98D35CD98E78D48B63A05AF6E4E4DEA',
'8433A94AEDB6380AC8D4610AF643FB0E5220C5CB',
'BEA77D1E59CF18DCE22AD9A2FAD52948FD7A9EFA',
'BFECB8CE89A312D2EF4AFC64A63847AE11C6F69E',
'DDE03348075512796241389DFEA5560C20A3D2A2EAC95C894E7BBED5E85A0ACC',
'FAD482DED2E25CE9E1DD3D3ECC3227AF714BDFBBDE04347DBC1B21D6A3670405',
'AA124A4B4DF12B34E74EE7F6C683B2EBEC4CE9A8EDCF9BE345823B4FDCF5D868',
'59E1EDF4D82FAE4978E97512B0331B7EB21DD4B838B850BA46794D9C7A2C0983',
'6285FFB5F98D35CD98E78D48B63A05AF6E4E4DEA',
'8433A94AEDB6380AC8D4610AF643FB0E5220C5CB',
'BEA77D1E59CF18DCE22AD9A2FAD52948FD7A9EFA',
'BFECB8CE89A312D2EF4AFC64A63847AE11C6F69E')
| where Timestamp > ago(30d)
//ref:https://github.com/SigmaHQ/sigma/pull/4151/files
```
