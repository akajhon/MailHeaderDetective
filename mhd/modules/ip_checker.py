import httpx
import os
from os.path import join, dirname
from maltiverse import Maltiverse
from dotenv import load_dotenv
import concurrent.futures

def query_abuseipdb(ip, abuseipdb_key):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&verbose"
        headers = {"Key": abuseipdb_key, "Accept": "application/json"}
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            abuseipdb_response = response.json()
            confidence_score = abuseipdb_response["data"]["abuseConfidenceScore"]
            if confidence_score > 1 and confidence_score <=25:
                return 'Suspicious'
            elif confidence_score > 25 and confidence_score <=100:
                return 'Malicious'
            else:
                return 'Safe'
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_abuseipdb: {e}")
        return "Error"

def query_ipqualityscore(ip, ipqualityscore_key):
    try:
        url = f"https://ipqualityscore.com/api/json/ip/{ipqualityscore_key}/{ip}"
        response = httpx.get(url)
        if response.status_code == 200:
            ipquality_response = response.json()
            fraud_score = ipquality_response["fraud_score"]
            if fraud_score >= 75 and fraud_score < 88:
                return 'Suspicious'
            elif fraud_score >= 88:
                return 'Malicious'
            else:
                return 'Safe'
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_ipqualityscore: {e}")
        return "Error"

def query_vt(ip, vt_key):
    try:
        url = f"https://virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": vt_key}
        response = httpx.get(url, headers=headers)
        if response.status_code == 200:
            vt_response = response.json()
            reputation = vt_response["data"]["attributes"]["reputation"]
            total_votes = vt_response["data"]["attributes"]["total_votes"]
            if reputation is not None:
                if reputation >= 95:
                    reputation_result = 'Safe'
                elif 75 <= reputation < 95:
                    reputation_result = 'Suspicious'
                else:
                    reputation_result = 'Malicious'
            else:
                reputation_result = "Not Found"
            if total_votes['malicious'] > total_votes['harmless']:
                votes_result = 'Malicious'
            elif total_votes['harmless'] > total_votes['malicious']:
                votes_result = 'Safe'
            else:
                votes_result = 'Undetermined'
            if reputation_result == votes_result:
                return reputation_result
            else:
                if 'Undetermined' in [reputation_result, votes_result] or 'Not found on VT' in [reputation_result, votes_result]:
                    return 'Suspicious'
                else:
                    return 'Suspicious'
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_vt: {e}")
        return "Error"

def query_maltiverse(ip, maltiverse_api):
    try:
        maltiverse_response = maltiverse_api.ip_get(ip)
        maltiverse_classification = maltiverse_response["classification"]
        if maltiverse_classification == 'malicious':
            return 'Malicious'
        elif maltiverse_classification == 'suspicious':
            return 'Suspicious'
        elif maltiverse_classification == 'unknown':
            return "Not Found"
        else:
            return 'Safe'
    except Exception as e:
        print(f"[!] Error in query_maltiverse: {e}")
        return "Error"

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
        print(f"[!] Error in query_ip_services: {e}")
        return "Error"