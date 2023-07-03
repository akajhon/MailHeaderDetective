import httpx
import os
import base64
from os.path import join, dirname
from dotenv import load_dotenv
from maltiverse import Maltiverse
import concurrent.futures

def query_vt(url, vt_key):
    try: 
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_vt = f"https://virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": vt_key}
        response = httpx.get(url_vt, headers=headers)
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
                if 'Undetermined' in [reputation_result, votes_result] or 'Not Found' in [reputation_result, votes_result]:
                    return 'Suspicious'
                else:
                    return 'Suspicious'
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_vt: {e}")
        return "Error"

def query_phishtank(url):
    try:
        phishtank_url = 'https://checkurl.phishtank.com/checkurl/'
        phishtank_params = {'url': {url}, 'format': 'json'}
        response = httpx.post(phishtank_url, data=phishtank_params)
        if response.status_code == 200:
            phishtank_response = response.json()
            in_database = phishtank_response['results']['in_database']
            if in_database:
                return 'Reported'
            else:
                return 'Not Reported'
        return "Not Found"
    except Exception as e:
        print(f"[!] Error in query_phishtank: {e}")
        return "Error"

def query_maltiverse(url, maltiverse_api):
    try:
        maltiverse_response = maltiverse_api.url_get(url)

        if 'Not Found' in maltiverse_response['message']:
            return "Not Found"
        else:
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

def query_url_services(url):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    maltiverse_api = Maltiverse(auth_token=os.getenv("MALTIVERSE"))
    vt_key = os.getenv("VIRUSTOTAL")

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            vt_future = executor.submit(query_vt, url, vt_key)
            phishtank_future = executor.submit(query_phishtank, url)
            maltiverse_future = executor.submit(query_maltiverse, url, maltiverse_api)

            results = {
                "vt": vt_future.result(),
                "phishtank": phishtank_future.result(),
                "maltiverse": maltiverse_future.result(),
            }

        return results

    except Exception as e:
        print(f"[!] Error in query_url_services: {e}")
        return "Error"