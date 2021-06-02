from dnsServer import DnsServer

# Localhost IP
ip = '127.0.0.1'

dns = DnsServer(ip)
dns.run()