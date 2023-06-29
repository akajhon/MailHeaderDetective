import httpx
import os
import base64
from os.path import join, dirname
from dotenv import load_dotenv
from maltiverse import Maltiverse

def query_url_services(url):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    maltiverse_api = Maltiverse(auth_token=os.getenv("MALTIVERSE"))
    vt_key = os.getenv("VIRUSTOTAL")

    try:
        results = {}
        # Query VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_vt = f"https://virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": vt_key}
        response = httpx.get(url_vt, headers=headers)
        if response.status_code == 200:
            vt_response = response.json()
            if 'malicious' in vt_response:
                vt_score = vt_response["data"]["attributes"]["last_analysis_stats"]["malicious"]
                results['vt'] = vt_score
            else:
                results['vt'] = "Not found on VT"

        # Check URLs in phishtank API
        phishtank_url = 'https://checkurl.phishtank.com/checkurl/'
        phishtank_params = {'url': {url}, 'format': 'json'}
        response = httpx.post(phishtank_url, data=phishtank_params)
        if response.status_code == 200:
            phishtank_response = response.json()
            if 'in_database' in phishtank_response:
                phishtank_score =  phishtank_response['results']['in_database']
                results['phishtank'] = phishtank_score
            else:
                results['phishtank'] = "Not found on Phishtank"

        # Query Maltiverse
        maltiverse_response = maltiverse_api.url_get(url)
        if 'classification' in maltiverse_response:
            classification = maltiverse_response["classification"]
            results["maltiverse"] = classification
        else:
            results["maltiverse"] = "Not found on Maltiverse"

        return results

    except Exception as e:
        return "error"

#query_url_services('faq.tomorrowlandbrasil.com')