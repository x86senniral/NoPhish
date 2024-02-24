from requests_html import HTMLSession
import whois
from datetime import datetime
import ssl
import socket
from Colors import get_color
import time

suspicious_points = 0


def cmdsnr_intro():
    print(f"The cmdsnr Checker uses {get_color('BLUE')}Age, Certificates, Page Parsing (and more..){get_color('RESEt')} techniques.\n By the end you will receive the amount of 'suspicious' points gathered.")

def check_ssl_certificate(domain):
    global suspicious_points
    context = ssl.create_default_context()
    try:
        # Added timeout parameter to the create_connection call
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()

                country_name = state_or_province = locality = organization = common_name = dns_names = ""

                # Parsing Subject
                for subject in certificate['subject']:
                    for key, value in subject:
                        if key == 'countryName':
                            country_name = value
                        elif key == 'stateOrProvinceName':
                            state_or_province = value
                        elif key == 'localityName':
                            locality = value
                        elif key == 'organizationName':
                            organization = value
                        elif key == 'commonName':
                            common_name = value
                
                dns_entries = [entry[1] for entry in certificate.get('subjectAltName', ())]
                dns_names = ", ".join(dns_entries)

                print(f"{get_color('BLUE')}Valid SSL certificate found{get_color('RESET')} for {domain}.")
                print("\nInfos:")
                print(f"Country Name:             {country_name}")
                print(f"State or Province:        {state_or_province}")
                print(f"Locality (City):          {locality}")
                print(f"Organization:             {organization}")
                print(f"Common Name:              {common_name}")
                print(f"DNS Names:                {dns_names}\n\n")
                return True
    except Exception as e:
        print(f"SSL check failed for {domain}: {e}")
        suspicious_points += 2
        return False

def analyze_website(url):
    cmdsnr_intro()
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://' + url
    time.sleep(5)
    global suspicious_points
    domain_name = url.split("//")[-1].split("/")[0]
    is_certificate_valid = check_ssl_certificate(domain_name)
    if is_certificate_valid:
        print(f"SSL certificate has been {get_color('BLUE')}found{get_color('RESET')} for {domain_name}")
    else:
        print(f"{get_color('RED')}No SSL certificate found{get_color('RESET')} for {domain_name}")
    time.sleep(5)
    try:
        domain_info = whois.whois(domain_name)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_years = (datetime.now() - creation_date).days / 365.25
        print(f"Domain {domain_name} is approximately {age_years:.2f} years old.")
        if age_years < 1:
            print(f"Domain is less than a year old. {get_color('RED')}+ 3 Suspicious.{get_color('RESET')}\n")
            suspicious_points += 3
    except Exception as e:
        print(f"Error retrieving WHOIS data for {domain_name}, a suspicious point will be added.\n")
        suspicious_points += 1
    time.sleep(5)
    if len(url) >= 20:
        print(f"Link exceeds 20 characters.  {get_color('RED')}+ Suspicious{get_color('RESET')}\n")
        suspicious_points += 1
    else:
        print(f"{get_color('BLUE')}Passed{get_color('RESET')} character Test\n")
    session = HTMLSession()
    try:
        r = session.get(url, timeout=30)
        r.html.render(sleep=1, timeout=30)
        password_fields = r.html.find('input[type="password"]')
        if password_fields:
            print(f"The website seems to have a login feature.   {get_color('RED')}+ Suspicious{get_color('RESET')}\n")
            suspicious_points += 2
        else:
            print("No obvious login feature found.\n")
    except Exception as e:
        print(f"An error occurred while trying to analyze the website: {e}\n Suspicious point will be added.\n")
        suspicious_points += 1
    finally:
        session.close()
    print(f"Suspicious Points (cmdsnr Checker): {get_color('RED')}{suspicious_points}{get_color('RESET')}\n")
    time.sleep(3)
    if suspicious_points >= 5:
        print(f"The website exceeds {suspicious_points} suspicious points. Deemed {get_color('RED')} possibly not safe.{get_color('RESET')}\n")
    elif suspicious_points >= 3:
        print(f"There might be some risk involved visiting {url} as it has gathered {suspicious_points} suspicious points.\n If there is a login feature found / involved it is generally not recommended to share any of your personal informations.\n If some of the features failed to execute such as the whois or or auth checker, it should raise suspicions as well.")
    else:
        print(f"{get_color('BLUE')}No direct threats found by cmdsnr Checker.{get_color('RESET')}\n")
