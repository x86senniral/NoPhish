import requests
from prettytable import PrettyTable
import socket
from Colors import get_color
    
# Get site IP
def resolve_url_to_ip(url):
    try:
        domain = url.split('//')[-1].split('/')[0] 
        ip_address = socket.gethostbyname(domain)  
        return ip_address
    except socket.gaierror:
        return None


def check_ip_reputation(api_key, ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        result = response.json()
        data = result['data']
        
        # Create a table
        table = PrettyTable()
        table.field_names = ["Attribute", "Value"]
        table.add_row(["IP Address", data['ipAddress']])
        table.add_row(["Is Public", data['isPublic']])
        table.add_row(["IP Version", data['ipVersion']])
        table.add_row([f"{get_color('RED')}Is Whitelisted{get_color('RESET')}", data['isWhitelisted']])
        table.add_row(["Abuse Confidence Score", data['abuseConfidenceScore']])
        table.add_row(["Country Code", data['countryCode']])
        table.add_row(["ISP", data['isp']])
        table.add_row(["Domain", data['domain']])
        table.add_row(["Is Tor", data['isTor']])
        table.add_row([f"{get_color('RED')}Total Reports{get_color('RESET')}", data['totalReports']])
        table.add_row(["Num Distinct Users", data['numDistinctUsers']])
        table.add_row(["Last Reported At", data['lastReportedAt']])
        
        return table
    else:
        print(f"Error: HTTP {response.status_code} - {response.reason}")

def check_IP_AbuseIPDB(api_key,url):
    ip_address = resolve_url_to_ip(url)
    if ip_address:
        print(f"Resolved IP Address: {ip_address}")
        return check_ip_reputation(api_key,ip_address)
    else:
        return "Unable to resolve IP address."