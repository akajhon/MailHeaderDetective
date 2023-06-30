import httpx
import os
from os.path import join, dirname
from dotenv import load_dotenv
import concurrent.futures

def query_virustotal(hash, API_KEY):
    headers_vt = {"accept": "application/json","X-Apikey": API_KEY}
    base_url = "https://www.virustotal.com/api/v3/"
    url = base_url + "search?query=" + hash
    response = httpx.get(url, headers=headers_vt)
    if response.status_code == 200:
        result = response.json()
        if result['data']:  # verificar se a lista 'data' não está vazia
            return result['data'][0]['attributes']['last_analysis_stats']['malicious'] if 'malicious' in result['data'][0]['attributes']['last_analysis_stats'] else "Not found on VT"
    return "No data from VT"  # retornar alguma coisa se a lista 'data' estiver vazia

def query_hybrid_analysis(hash, API_KEY):
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
        if result:  # verificar se a lista 'result' não está vazia
            threat_score = result[0]['threat_score']
            return threat_score if 'threat_score' in result[0] else "Not found on HA"
    return "No data from HA"  # retornar alguma coisa se a lista 'result' estiver vazia


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
        print(f"Erro ao processar o hash: {e}")
        # results = {
        #     "vt": None,
        #     "ha": None
        # }
        # return results

# analysis_256 = query_hash_services('463b5477ff96ab86a01ba49bcc02b539')
# print(analysis_256)
