# PaganMarble
Malicious Port Monitor Detection - T1547.010

Compile as x64 and run from an elevated command prompt. The app will check dll's in ```HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors``` - checking the dll version and company info. It will throw an alert if not by Microsoft Corporation, or if it's not found in System32.

It'll also check for processes with the parent process of ```spoolsv```. Keep in mind just because an alert/warning is thrown does not mean it's malicious.
