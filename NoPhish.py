from Colors import get_color
from UrlCheck import checkURL,check_ip_reputation
import os
from AsciiArt import logo, Serpent, EYS, MGGL
from UrlCheck import abuse_ipdb_api

def Introduction():
    clear_screen()
    Intro = f"""{get_color('BLUE')}
▒█▄░▒█ █▀▀█ ▒█▀▀█ ░▀░ █▀▀ █░░█ 
▒█▒█▒█ █░░█ ▒█▄▄█ ▀█▀ ▀▀█ █▀▀█ 
▒█░░▀█ ▀▀▀▀ ▒█░░░ ▀▀▀ ▀▀▀ ▀░░▀
{get_color('RESET')}\
By: CmdSNR
Version: 1.5 [ BETA ]
{get_color('RED')}NOTE: Some APIs might have daily limits.{get_color('RESET')}{get_color('GREEN')}\nUse command "manual" to receive everything you need to know about how to use the scanner.{get_color('RESET')}
Use "help" to display the help commands all over again. 
Use "clear" to clear the screen.
    """
    print(Intro)
    #time.sleep(5)
    CommandLine()


"""
------------------- ESSENTIALS -------------------
"""

def Mann():
    mann = ['Get Started','Fix Errors','Required APIs & How To Get Them']
    manual = {
        
    }
    print(f"{get_color('GREEN')}For the Manual use numbers to select a specific options.{get_color('RESET')}")
    for index,content in enumerate(mann):
        print(f'{index + 1}. {content}\n')
    try:
        user_input = int(input('Select option: '))
        match user_input:
            case 1:
                print('Visit https://www.nrelm.com/nophish for full details.')
            case 2:
                print("Visit: https://github.com/sytaxus/NoPhish/issues | if you don't see your issue there, please open a ticket and be as specific as possible.")
            case 3:
                print('Visit https://www.nrelm.com/nophish for full details.\nRequired APIs:\n\n1. Google Safe Browsing API : https://developers.google.com/safe-browsing/v4/get-started \n\n2. Rapid API (Exerra):https://rapidapi.com/Exerra/api/exerra-phishing-check/ \n\n3. IpQualityScore API: https://www.ipqualityscore.com/documentation/proxy-detection-api/overview \n\n4. AbuseIPDB API: https://www.abuseipdb.com/api.html \n\n5. Url.io API: https://urlscan.io/docs/api/ \n\n6. VirusTotal API: https://www.virustotal.com/ \n')
    except Exception as e:
        print(f'Error: {e}')


def CommandLine():
    commands_Available = ['Scan For Phishing', 'Manual', 'Check IP Reputation', 'Help', 'Clear', 'Exit']
        
    command_keys = {
        'manual':2,
        'help':4,
        'clear': 5,
        'exit': 6
    }

    print('Select the option of choice.')
    for index, command in enumerate(commands_Available):
        print(f"{index + 1}. {command}")
    
    while True: 
        userinput = input(f"{get_color('BLUE')}NoPish >{get_color('RESET')} ").strip().lower()  
        if userinput.isdigit():
            choice = int(userinput)
        elif userinput in command_keys:
            choice = command_keys[userinput] 
        else:
            print("Invalid command. Please enter a number or a recognized command.")
            continue  

        if choice == 1:
            clear_screen()
            logo()
            print(checkURL())
        elif choice == 2:
            clear_screen()
            MGGL()
            Mann()
        elif choice == 3:
            clear_screen()
            EYS()
            ip_address = input('Enter IP Address to check: ')
            result = check_ip_reputation(abuse_ipdb_api,ip_address)
            print(result)
        elif choice == 4:
            clear_screen()
            Introduction()
            for index, command in enumerate(commands_Available):
                print(f"{index + 1}. {command}")
        elif choice == 5:  
            clear_screen()
        elif choice == 6: 
            print("Exiting...")
            break
        else:
            print("Invalid option. Please select a valid number or command.")

def clear_screen():
    # Check if the operating system is Windows
    if os.name == 'nt':
        _ = os.system('cls')
    # Otherwise, it's assumed to be Unix/Linux
    else:
        _ = os.system('clear')


if __name__ == "__main__":
    Introduction()
