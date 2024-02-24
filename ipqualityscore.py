import requests
from urllib.parse import urlparse
from Colors import get_color


def get_domain_from_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    domain = domain.split('@')[-1]  # Remove any user info
    domain = domain.split(':')[0]  # Remove any port info
    domain = domain.rstrip('/')  # Remove trailing slash if present
    return domain

def check_ipqualityscore(original_url, api_key):
    domain = get_domain_from_url(original_url)
    api_url = f"https://ipqualityscore.com/api/json/url/{api_key}/{domain}"
    
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            # Extract only the required attributes
            filtered_data = {
                f"{get_color('RED')}Unsafe{get_color('RESET')}": data.get('unsafe'),
                f"{get_color('RED')}Malware{get_color('RESET')}": data.get('malware'),
                f"{get_color('RED')}Phishing{get_color('RESET')}": data.get('phishing'),
                f"{get_color('RED')}Risk Score (From 0 to 100){get_color('RESET')}": data.get('risk_score'),
                "Category": data.get('category'),
                "Domain": data.get('domain'),
                "IP Address": data.get('ip_address'),
                f"{get_color('RED')}Suspicious{get_color('RESET')}": data.get('suspicious'),
                "Country Code": data.get('country_code'),
            }
            return filtered_data
        else:
            return {"Error": f"Received a {response.status_code} status code from the API."}
    except Exception as e:
        return {"Error": f"An exception occurred: {str(e)}."}


