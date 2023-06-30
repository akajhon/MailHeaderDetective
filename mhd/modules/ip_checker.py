import httpx
import os
from os.path import join, dirname
from maltiverse import Maltiverse
from dotenv import load_dotenv
import concurrent.futures

def query_abuseipdb(ip, abuseipdb_key):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose"
    headers = {"Key": abuseipdb_key, "Accept": "application/json"}
    response = httpx.get(url, headers=headers)
    if response.status_code == 200:
        abuseipdb_response = response.json()
        return abuseipdb_response["data"]["abuseConfidenceScore"] if 'abuseConfidenceScore' in abuseipdb_response else "Not found on AbuseIPDB"

def query_ipqualityscore(ip, ipqualityscore_key):
    url = f"https://ipqualityscore.com/api/json/ip/{ipqualityscore_key}/{ip}"
    response = httpx.get(url)
    if response.status_code == 200:
        ipquality_response = response.json()
        return ipquality_response["fraud_score"] if 'fraud_score' in ipquality_response else "Not found on IpQualityScore"

def query_vt(ip, vt_key):
    url = f"https://virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    response = httpx.get(url, headers=headers)
    if response.status_code == 200:
        vt_response = response.json()
        return vt_response["data"]["attributes"]["reputation"] if 'reputation' in vt_response else "Not found on VT"

def query_maltiverse(ip, maltiverse_api):
    maltiverse_response = maltiverse_api.ip_get(ip)
    return maltiverse_response["classification"] if 'classification' in maltiverse_response else "Not Found on Maltiverse"

def query_ip_services(ip):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    abuseipdb_key = os.getenv("ABUSEIPDB")
    ipqualityscore_key = os.getenv("IPQUALITYSCORE")
    vt_key = os.getenv("VIRUSTOTAL")
    maltiverse_api = Maltiverse(auth_token=os.getenv("MALTIVERSE"))

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            abuseipdb_future = executor.submit(query_abuseipdb, ip, abuseipdb_key)
            ipqualityscore_future = executor.submit(query_ipqualityscore, ip, ipqualityscore_key)
            vt_future = executor.submit(query_vt, ip, vt_key)
            maltiverse_future = executor.submit(query_maltiverse, ip, maltiverse_api)

            results = {
                "abuseipdb": abuseipdb_future.result(),
                "ipqualityscore": ipqualityscore_future.result(),
                "vt": vt_future.result(),
                "maltiverse": maltiverse_future.result(),
            }

        return results

    except Exception as e:
        return "error"
