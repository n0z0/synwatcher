# honeypot

```ps
Get-NetAdapter | Select Name, InterfaceDescription, InterfaceGuid, ifIndex, Status

.\synwatcher.exe -iface "\Device\NPF_{A91E7D86-E24B-4761-94EF-DE993C6116BD}"
```

release update

```sh
git tag v0.1.0
git push origin --tags
go list -m github.com/n0z0/synwatcher@v0.1.0
```
