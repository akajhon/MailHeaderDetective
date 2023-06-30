import httpx
import os
from os.path import join, dirname
from dotenv import load_dotenv
import concurrent.futures

def query_hunterio(email, hunterio_key):
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunterio_key}"
    response = httpx.get(url)
    if response.status_code == 200:
        hunterio_response = response.json()
        score = hunterio_response["data"]["score"]
        gibberish = hunterio_response["data"]["gibberish"]
        email_status = hunterio_response["data"]["status"]
        if email_status != 'valid' or score <= 50:
            return 'Malicious'
        elif gibberish:
            return 'Suspicious'
        return "Safe"
    return "Not Found"

def query_ipqualityscore(email, ipqualityscore_key):
    url = f"https://www.ipqualityscore.com/api/json/email/{ipqualityscore_key}/{email}"
    response = httpx.get(url)
    if response.status_code == 200:
        ipquality_response = response.json()
        fraud_score = ipquality_response["fraud_score"]
        if fraud_score >= 75 and fraud_score < 90:
            return 'Suspicious'
        elif fraud_score >= 90:
            return 'Malicious'
        else:
            return 'Safe'
    return "Not Found"

def query_email_services(email):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    hunterio_key = os.getenv("HUNTER")
    ipqualityscore_key = os.getenv("IPQUALITYSCORE")

    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            hunterio_future = executor.submit(query_hunterio, email, hunterio_key)
            ipqualityscore_future = executor.submit(query_ipqualityscore, email, ipqualityscore_key)

            results = {
                "hunterio": hunterio_future.result(),
                "ipqualityscore": ipqualityscore_future.result(),
            }

        return results

    except Exception as e:
        print(e)
        return "error"
