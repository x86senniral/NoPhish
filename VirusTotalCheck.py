import requests


"""
ONLY ACCEPTS HTTP://
"""

def format_url_for_virustotal(url):
    if url.startswith('https://'):
        url = 'http://' + url[len('https://'):]
    elif not url.startswith('http://'):
        url = 'http://' + url
    return url

def virus_total_urlanalysis(original_url, api_key):
    url = format_url_for_virustotal(original_url)  
    headers = {
        'x-apikey': api_key
    }
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
    if response.status_code == 200:
        result = response.json()
        url_id = result['data']['id']
        return url_id
    else:
        print(f"Error submitting URL for analysis: {response.status_code}")
        return None

def get_analysis_report(url_id, api_key):
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/analyses/{url_id}', headers=headers)
    if response.status_code == 200:
        result = response.json()
        return result
    else:
        return f"Error: Code Response: {response.status_code}"
