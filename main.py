import re , json
import requests , time
from prettytable import *
import urllib3
import tldextract

WHOIS_APIKEY = "at_VLvmiwz0jb1NTOBR3CrmrvBWh9xnM"
URLSCAN_APIKEY = "1acca1ab-7766-4ae3-a8b1-21f69602833c"
VIRUSTOTAL_APIKEY = "8b6fa26d7c9e48fd89918bdaf3fec33260a807c5dadc8a67ad201805f0c4aa35"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ipPattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

def check_domain_info(domains):
    api_endpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    results = []

    for domain in domains:
        api_url = f"{api_endpoint}?apiKey={WHOIS_APIKEY}&domainName={domain}&outputFormat=JSON"

        try:
            response = requests.get(api_url)
            data = response.json()

            if response.status_code == 200 and data.get("WhoisRecord", {}).get("registryData"):
                registry_data = data["WhoisRecord"]["registryData"]

                result = {
                    "domain": domain,
                    "whois_data": {
                        "Domain Name": registry_data.get("domainName", "N/A"),
                        "Registrar": registry_data.get("registrarName", "N/A"),
                        "Registration Date": registry_data.get("createdDate", "N/A"),
                        "Expiration Date": registry_data.get("expiresDate", "N/A"),
                        "Updated Date": registry_data.get("updatedDate", "N/A"),
                        "Name Servers": registry_data.get("nameServers", []),
                        "Status": registry_data.get("status", "N/A"),
                        "Registrant": registry_data.get("registrant", {}),
                        "Admin": registry_data.get("admin", {}),
                        "Technical": registry_data.get("technical", {}),
                        "Billing": registry_data.get("billing", {}),
                        "Zone": registry_data.get("zone", {}),
                        "Whois Server": registry_data.get("whoisServer", "N/A"),
                        "Referral URL": registry_data.get("referralURL", "N/A"),
                        "Registrar URL": registry_data.get("registrarURL", "N/A"),
                        "Creation Date": registry_data.get("createdDate", "N/A"),
                        "Emails": registry_data.get("emails", []),
                        "DNSSEC": registry_data.get("dnssec", "N/A"),
                        "Name": registry_data.get("name", "N/A"),
                        "Organization": registry_data.get("organization", "N/A"),
                        "Street": registry_data.get("street", "N/A"),
                        "City": registry_data.get("city", "N/A"),
                        "State": registry_data.get("state", "N/A"),
                        "Postal Code": registry_data.get("postalCode", "N/A"),
                        "Country": registry_data.get("country", "N/A"),
                    },
                    "error": None
                }

                results.append(result)
            else:
                error_message = data.get("ErrorMessage", "Unknown error")
                results.append({"domain": domain, "whois_data": None, "error": f"Error: {error_message}"})

        except Exception as e:
            results.append({"domain": domain, "whois_data": None, "error": f"Error: {str(e)}"})

    for result in results:
        print(f"\nDomain: {result['domain']}")
        print("-" * 100)  # Print nine equal signs for separation

        if result['error']:
            print(f"Error: {result['error']}")
        else:
            print("Whois Data:")

            table = PrettyTable()

            # Define table columns
            table.field_names = ["Attributes", "Information"]
            table._max_width = {"Attributes": 30, "Information": 70}
            for key, value in result['whois_data'].items():
                table.add_row([f"{key}", f"{value}"])

        print(table)
        print("-" * 100)  # Print nine equal signs for separation


def check_url_info(url):
    headers = {"API-Key": URLSCAN_APIKEY }

    data = {"url": url,"visibility": "private" }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)

    scanlink = response.json()['api']

    response = requests.get(scanlink)
    verdict = "This URL has a malicious rating."
    try :
        if response.json()['verdicts']['overall']['malicious'] != False:
            verdict = "This URL is not malicious."
    except:
        pass

    print("-" * 100)
    print()
    print("URL SCAN Info : " , verdict,"\n")
    print("-" * 100)


# VIRUS TOTAL FUNC
def checkVirustotal(urls):
    try:

        vtBaseUrl = "https://www.virustotal.com/api/v3/urls/"

        url = f"{vtBaseUrl}{urls}"  # VT

        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_APIKEY
        }

        response = requests.get(url, headers=headers)
        json_file = json.loads(response.text)

        try:
            asOwner = json_file["data"]["attributes"]["as_owner"]
        except:
            asOwner = "None"

        lastAnalysisStats = json_file["data"]["attributes"]["last_analysis_stats"]
        isMalicious = json_file["data"]["attributes"]["last_analysis_stats"]["malicious"]

        returnJson = {
            "asOwner": asOwner,
            "lastAnalysisStats": lastAnalysisStats,
            "isMalicious": isMalicious,
            "error": False
        }
    except:
        returnJson = {
            "asOwner": "Error",
            "lastAnalysisStats": {"Error": "Error with VirusTotal"},
            "isMalicious": 0,
            "error": True
        }

print('''
░██╗░░░░░░░██╗██████╗░██████╗░██╗░░░██╗██████╗░░░███╗░░░██████╗░█████╗░░░██╗██╗███╗░░██╗  ████████╗░█████╗░░█████╗░██╗░░░░░
░██║░░██╗░░██║╚════██╗██╔══██╗██║░░░██║██╔══██╗░████║░░██╔════╝██╔══██╗░██╔╝██║████╗░██║  ╚══██╔══╝██╔══██╗██╔══██╗██║░░░░░
░╚██╗████╗██╔╝░█████╔╝██████╦╝██║░░░██║██████╔╝██╔██║░░╚█████╗░██║░░╚═╝██╔╝░██║██╔██╗██║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
░░████╔═████║░░╚═══██╗██╔══██╗██║░░░██║██╔══██╗╚═╝██║░░░╚═══██╗██║░░██╗███████║██║╚████║  ░░░██║░░░██║░░██║██║░░██║██║░░░░░
░░╚██╔╝░╚██╔╝░██████╔╝██████╦╝╚██████╔╝██║░░██║███████╗██████╔╝╚█████╔╝╚════██║██║░╚███║  ░░░██║░░░╚█████╔╝╚█████╔╝███████╗
░░░╚═╝░░░╚═╝░░╚═════╝░╚═════╝░░╚═════╝░╚═╝░░╚═╝╚══════╝╚═════╝░░╚════╝░░░░░░╚═╝╚═╝░░╚══╝  ░░░╚═╝░░░░╚════╝░░╚════╝░╚══════╝''')

# check_domain_info(["sece.ac.in"])
# check_url_info("https://cutt.ly/qvsxDIo")
checkVirustotal("https://github.com/sharmi-01/Phising_detection/blob/main/Main_Phish.py")
