# FAT Virtual File System Emulation

This project is a basic implementation of an AES256-encrypted virtual FAT file system for emulating TTPs used by certain groups.

The encryption key is store in Registry in a user-specified key under HKCU.

This project helps emulate the following TTPs:
* Hide Artifacts: Hidden File System ([T1564.005](https://attack.mitre.org/techniques/T1564/005/)).
* Data Staged: Local Data Staging ([T1074.001](https://attack.mitre.org/techniques/T1074/001/)).
* Query Registry ([T1012](https://attack.mitre.org/techniques/T1012/)).
* Modify Registry ([T1112](https://attack.mitre.org/techniques/T1112/)).
* Obfuscated Files or Information ([T1027](https://attack.mitre.org/techniques/T1027/)).
* Hide Artifacts: Hidden Files and Directories ([T1564.001](https://attack.mitre.org/techniques/T1564/001/)).
* Archive Collected Data: Archive via Library ([T1560.002](https://attack.mitre.org/techniques/T1560/002/)).
