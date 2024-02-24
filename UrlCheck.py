from VirusTotalCheck import virus_total_urlanalysis, get_analysis_report
from Abuse_IPDB import check_ip_reputation, check_IP_AbuseIPDB
from GoogleSafeBrowsing import display_google_safe_browsing_results
from prettytable import PrettyTable
from Colors import get_color
from ipqualityscore import check_ipqualityscore
from urlio import urlscan_io_analysis
from RapidAPIs import check_exerra_phishing
import time
from cmdsnrChecker import analyze_website

"""
CHANGE THIS -----------------------
"""
abuse_ipdb_api = "API KEY HERE"

def checkURL():
    # APIS
    global abuse_ipdb_api
    """
    CHANGE THESE -------------------------
    """
    ipscore_api = "API KEY HERE"
    api_key_urlscan = "API KEY HERE"
    api_key_gs = "API KEY HERE" 
    api_key_virustotal = "API KEY HERE"
    api_ExerraPhish = "API KEY HERE"

    space = "======" * 12

    url = input('Enter URL to scan: ') 

    # CHECKING WITH RAPID FAST APIs.
    print(space)
    print("Checking with Exerra Phishing Check...\n")
    exerra_result_table = check_exerra_phishing(url,api_ExerraPhish)
    print(exerra_result_table)
    
    time.sleep(5)

    #Ip quality score.
    print(space)
    print('Checking with IP QUALITY SCORE. \n')
    data = check_ipqualityscore(url, ipscore_api)

    if data.get("success", True):  # Default to True for backward compatibility
        ipqs_table = PrettyTable()
        ipqs_table.field_names = ["Attribute", "Value"]
        for key, value in data.items():
            ipqs_table.add_row([key, value])
        print(ipqs_table)
    else:
        print(data["message"])

    #ABUSEIPDB  
    print(space)
    time.sleep(5)
    print("Checking IP reputation with AbuseIPDB...\n")    
    abuse_ipdb_result = check_IP_AbuseIPDB(abuse_ipdb_api,url)
    print(abuse_ipdb_result)
    print(space)

    #GSB
    print("\nNext Scan GSB in:", end=" ", flush=True)
    for i in range(5,-1,-1):
        print(f"\rNext Scan With GSB in: {i}", end=" ", flush=True)
        time.sleep(1)
        if i == 0:
            print(f"\n{get_color('BLUE')}Google Safe Browsing (GSB) Verdict:{get_color('RESET')}")
    display_google_safe_browsing_results(url, api_key_gs)
    print(space)

    # url io
    print(f"\nPerforming {get_color('BLUE')}urlScan.io{get_color('RESET')} scan:\n")
    urlscan_io_analysis(url, api_key_urlscan)

    print(space)

    print(analyze_website(url))

    print(space)

    # VirusTotal
    print("\nPerforming VirusTotal URL analysis In:", end=" ", flush=True)
    for i in range(5,-1,-1):
        print(f"\rPerforming VirusTotal URL analysis In: {i}", end=" ", flush=True)
        time.sleep(1)
        if i == 0:
            print(f"\n{get_color('BLUE')}Virus Total Verdict:{get_color('RESET')}")

        

    url_id = virus_total_urlanalysis(url, api_key_virustotal)
    if url_id:
        report = get_analysis_report(url_id, api_key_virustotal)
        if 'data' in report:
            stats = report['data']['attributes']['stats']
            malicious = stats['malicious']
            suspicious = stats['suspicious']
            harmless = stats['harmless']
            undetected = stats['undetected']
            total_scans = malicious + suspicious + harmless + undetected

            vt_table = PrettyTable()
            vt_table.field_names = ["Category", "Count"]
            vt_table.add_row([f"{get_color('RED')}Malicious{get_color('RESET')}", f"{malicious} (out of {total_scans})"])
            vt_table.add_row([f"{get_color('ORANGE')}Suspicious{get_color('RESET')}", suspicious])
            vt_table.add_row(["Harmless", harmless])
            vt_table.add_row(["Undetected", undetected])
            if malicious >= 7:
                print(f"\nNOTE: Even though {harmless} anti-viruses did not flag it, since the number of malicious reports exceeds at least 7, there is a high chance of it being an actual phishing or malicious page.")
            elif harmless == 0 and malicious == 0:
                print('There might have been an error while scanning with virus total, try scanning again and see if you get any results. If not then results should be accurate.')
            else:
                print("None")

            return vt_table
        else:
            print("Analysis result unavailable.")
    else:
        print("Error submitting URL for analysis.")

