import nmap

def network_scan(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')
    return nm.all_hosts()

def port_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-65535')
    return nm[ip]

def detect_services(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-65535', '-sV')
    return nm[ip]

