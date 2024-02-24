from prettytable import PrettyTable
import requests
from Colors import get_color

"""
EXERRA API

REQUIRES HTTP:// / HTTPS:// 
"""

def format_url_for_exerra(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def check_exerra_phishing(original_url,api_key):
    url = format_url_for_exerra(original_url)
    api_url = "https://exerra-phishing-check.p.rapidapi.com/"
    querystring = {"url": url}
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": "exerra-phishing-check.p.rapidapi.com"
    }
    
    response = requests.get(api_url, headers=headers, params=querystring)
    data = response.json()
    
    exerra_table = PrettyTable()
    exerra_table.field_names = ["Attribute", "Value"]
    
    status = data.get('status', 'N/A')
    is_scam = data.get('data', {}).get('isScam', 'N/A')
    domain = data.get('data', {}).get('domain', 'N/A')
    detection_type = data.get('data', {}).get('detection', {}).get('type', 'N/A')
    
    exerra_table.add_row(["Status", status])
    exerra_table.add_row(["Domain", domain])
    exerra_table.add_row([f"{get_color('RED')}Is Scam?{get_color('RESET')}", is_scam])
    exerra_table.add_row(["Detection Type", detection_type])
    
    return exerra_table

"""
openSQUAT API

"""

