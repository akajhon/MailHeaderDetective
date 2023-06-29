import httpx
import os
from os.path import join, dirname
from maltiverse import Maltiverse
from dotenv import load_dotenv

def query_ip_services(ip):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    abuseipdb_key = os.getenv("ABUSEIPDB")
    ipqualityscore_key = os.getenv("IPQUALITYSCORE")
    vt_key = os.getenv("VIRUSTOTAL")
    maltiverse_api = Maltiverse(auth_token=os.getenv("MALTIVERSE"))

    try:
        results = {}
        # Query AbuseIPDB API
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose"
        headers = {"Key": abuseipdb_key, "Accept": "application/json"}
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            abuseipdb_response = response.json()
            if 'abuseConfidenceScore' in abuseipdb_response:
                abuseipdb_score = abuseipdb_response["data"]["abuseConfidenceScore"]
                results["abuseipdb"] = abuseipdb_score
            else:
                results["abuseipdb"] = "Not found on AbuseIPDB"

        # Query ipqualityscore API
        url = f"https://ipqualityscore.com/api/json/ip/{ipqualityscore_key}/{ip}"
        response = httpx.get(url)
        if response.status_code == 200:
            ipquality_response = response.json()
            if 'fraud_score' in abuseipdb_response:
                ipQuality_score = ipquality_response["fraud_score"]
                results["ipqualityscore"] = ipQuality_score
            else:
                results["ipqualityscore"] = "Not found on IpQualityScore"

        # Query VT API
        url = f"https://virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": vt_key}
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            vt_response = response.json()
            if 'reputation' in vt_response:
                vt_score = vt_response["data"]["attributes"]["reputation"]
                results["vt"] = vt_score
            else:
                results["vt"] = "Not found on VT"

        # Query Maltiverse
        maltiverse_response = maltiverse_api.ip_get(ip)
        if 'classification' in maltiverse_response:
            classification = maltiverse_response["classification"]
            results["maltiverse"] = classification
        else:
            results["maltiverse"] = "Not Found on Maltiverse"

        return results

    except Exception as e:
        return "error"

#query_ip_services('023.03.30.06')