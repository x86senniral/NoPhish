import requests
import json
import time
from Colors import get_color

def urlscan_io_analysis(url, api_key_urlscan):
    submit_url = 'https://urlscan.io/api/v1/scan/'
    headers = {'API-Key': api_key_urlscan, 'Content-Type': 'application/json'}
    data = {'url': url, 'visibility': 'public'}
    response = requests.post(submit_url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        response_data = response.json()
        scan_uuid = response_data['uuid']
        print(f"URLScan.io scan submitted successfully. Scan UUID: {scan_uuid}")

        max_retries = 10
        attempt = 0
        while attempt < max_retries:
            attempt += 1  
            print(f"\rWaiting for URLScan.io results. Attempt {attempt}/{max_retries}...", end='', flush=True)
            time.sleep(10)  # Wait for 10 seconds before checking again
            result_url = f'https://urlscan.io/api/v1/result/{scan_uuid}/'
            result_response = requests.get(result_url)

            if result_response.status_code == 200:
                result_data = result_response.json()
                page_country = result_data.get('page', {}).get('country', 'Country not available')
                server_ip = result_data.get('page', {}).get('ip', 'IP not available')
                print(f"\nServer IP: {server_ip}, Page Country: {page_country}")

                verdicts = result_data.get('verdicts', {})
                if 'overall' in verdicts:
                    overall_verdict = verdicts['overall']
                    is_malicious = overall_verdict.get('malicious', False)
                    print(f"{get_color('RED')}The website is deemed malicious by URLScan.io.{get_color('RESET')}" if is_malicious else "The website is not deemed malicious | has no classification by URLScan.io.")
                else:
                    print("The website has no classification by URLScan.io.")
                return  
            elif attempt == max_retries:
                print("\nFinal attempt to retrieve results failed. Moving on.")
                return 
            else:
                print("", end='', flush=True) 
                continue  

    else:
        print(f"\nFailed to submit URL for scanning to URLScan.io. Status code: {response.status_code}")


def urlIO():
    api_key = 'b9e82d19-c7ca-478d-9e98-1bc94f514168'
    url_to_scan = 'http://joicedate.com/'
    submit_url = 'https://urlscan.io/api/v1/scan/'
    headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
    data = {'url': url_to_scan, 'visibility': 'public'}

    response = requests.post(submit_url, headers=headers, data=json.dumps(data))

    if response.status_code == 200:
        response_data = response.json()
        scan_uuid = response_data['uuid']
        print(f"Scan submitted successfully. Scan UUID: {scan_uuid}")
        max_retries = 6
        attempt = 0
        while attempt < max_retries:
            print(f"Attempt {attempt + 1}/{max_retries}: Waiting for the scan to complete...")
            time.sleep(10)
            result_url = f'https://urlscan.io/api/v1/result/{scan_uuid}/'
            result_response = requests.get(result_url)
            if result_response.status_code == 200:
                result_data = result_response.json()
                page_country = result_data.get('page', {}).get('country', 'Country not available')
                server_ip = result_data.get('page', {}).get('ip', 'IP not available')
                print(f"Server IP: {server_ip}, Page Country: {page_country}")
                if 'verdicts' in result_data and 'overall' in result_data['verdicts']:
                    overall_verdict = result_data['verdicts']['overall']
                    if 'malicious' in overall_verdict and overall_verdict['malicious']:
                        print("The website is deemed malicious.")
                    else:
                        print("The website is not deemed malicious based on the overall verdict.")
                break
            else:
                print("Scan is not finished yet or another error occurred.")
            attempt += 1
        if attempt == max_retries:
            print("Exceeded maximum retry attempts without successful scan completion.")
    else:
        print("Failed to submit URL for scanning")
        print(response.text)
