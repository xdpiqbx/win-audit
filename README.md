# win-audit
```powershell

powershell

Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command Set-Location '$PWD'"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Windows_Vuln_Check_v2.ps1

```