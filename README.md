# Dns-Server
 A simple DNS server using Python.

## How to use
1. Run the `main.py` file using Python 3.
2. Open a PowerShell Window.
3. Run the following command: `Resolve-DnsName -Name howcode.org -Server <IP ADDRESS> -Type A`.
4. The results match with the `zones/howcode.org.zone` file.

## Important notes
1. The server only supports DNS A Records.
2. The server does not support request recursion and error flags.
