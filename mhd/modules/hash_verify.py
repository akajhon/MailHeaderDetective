import httpx
import os
from os.path import join, dirname
from dotenv import load_dotenv
import concurrent.futures

def query_virustotal(hash, API_KEY):
    try:
        headers_vt = {"accept": "application/json","X-Apikey": API_KEY}
        base_url = "https://www.virustotal.com/api/v3/"
        url = base_url + "search?query=" + hash
        vt_response = httpx.get(url, headers=headers_vt)
        if vt_response.status_code == 200:
            vt_response = vt_response.json()
            if not vt_response['data']:
                return "Not Found"
            else:
                attributes = vt_response["data"][0]["attributes"]
                reputation = attributes.get("reputation")
                total_votes = attributes.get("total_votes")
                if reputation is not None:
                    if reputation >= 95:
                        reputation_result = 'Safe'
                    elif 75 <= reputation < 95:
                        reputation_result = 'Suspicious'
                    else:
                        reputation_result = 'Malicious'
                else:
                    reputation_result = "Not found on VT"
                if total_votes is not None and isinstance(total_votes, dict):
                    malicious_votes = total_votes.get('malicious', 0)
                    harmless_votes = total_votes.get('harmless', 0)
                    if malicious_votes > harmless_votes:
                        votes_result = 'Malicious'
                    elif harmless_votes > malicious_votes:
                        votes_result = 'Safe'
                    else:
                        votes_result = 'Undetermined'
                else:
                    votes_result = 'Undetermined'
                if reputation_result == votes_result:
                    return reputation_result
                else:
                    if 'Undetermined' in [reputation_result, votes_result] or 'Not found on VT' in [reputation_result, votes_result]:
                        return 'Suspicious'
                    else:
                        return 'Suspicious'
        return "No Data from VT"
    except Exception as e:
        print(f"[!] Error in query_virustotal: {e}")
        return "Error"

def query_hybrid_analysis(hash, API_KEY):
    try:
        headers_ha = {
            'accept': 'application/json',
            'user-agent': 'Falcon Sandbox',
            'api-key': API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        url_ha = 'https://www.hybrid-analysis.com/api/v2/search/hash'
        data_ha = {'hash': hash}
        response = httpx.post(url_ha, headers=headers_ha, data=data_ha)
        if response.status_code == 200:
            result = response.json()
            if result: 
                threat_score = result[0].get('threat_score', None)
                if threat_score is not None:
                    if threat_score >= 30:
                        return 'Safe'
                    elif 30 < threat_score <= 70:
                        return 'Suspicious'
                    else:
                        return 'Malicious'
                else:
                    return "Not Found"
            return "Not Found"
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_hybrid_analysis: {e}")
        return "Error"

def query_hash_services(hash):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    ha_key = os.getenv("HYBRIDANALYSIS")
    vt_key = os.getenv("VIRUSTOTAL")

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            virustotal_future = executor.submit(query_virustotal, hash, vt_key)
            hybrid_analysis_future = executor.submit(query_hybrid_analysis, hash, ha_key)

            results = {
                "vt": virustotal_future.result(),
                "ha": hybrid_analysis_future.result()
            }
            return results
    except Exception as e:
        print(f"[!] Error in query_hash_services: {e}")
        return 'Error'
