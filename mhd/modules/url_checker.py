import httpx
import os
import base64
from os.path import join, dirname
from dotenv import load_dotenv
from maltiverse import Maltiverse
import concurrent.futures

def query_vt(url, vt_key):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url_vt = f"https://virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": vt_key}
    response = httpx.get(url_vt, headers=headers)
    if response.status_code == 200:
        vt_response = response.json()
        return vt_response["data"]["attributes"]["last_analysis_stats"]["malicious"] if 'malicious' in vt_response else "Not found on VT"

def query_phishtank(url):
    phishtank_url = 'https://checkurl.phishtank.com/checkurl/'
    phishtank_params = {'url': {url}, 'format': 'json'}
    response = httpx.post(phishtank_url, data=phishtank_params)
    if response.status_code == 200:
        phishtank_response = response.json()
        return phishtank_response['results']['in_database'] if 'in_database' in phishtank_response else "Not found on Phishtank"

def query_maltiverse(url, maltiverse_api):
    maltiverse_response = maltiverse_api.url_get(url)
    return maltiverse_response["classification"] if 'classification' in maltiverse_response else "Not found on Maltiverse"

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
        return "error"