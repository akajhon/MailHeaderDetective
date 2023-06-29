import httpx
import os
from os.path import join, dirname
from dotenv import load_dotenv

def query_email_services(email):
    dotenv_path = join(dirname(__file__), '.env')
    load_dotenv(dotenv_path, override=True)

    hunterio_key = os.getenv("HUNTER")
    ipqualityscore_key = os.getenv("IPQUALITYSCORE")

    try:
        results = {}
        #Query HunterIO API
        url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunterio_key}"
        response = httpx.get(url)
        if response.status_code == 200:
            hunterio_response = response.json()
            if 'score' in hunterio_response:
                hunterio_score = hunterio_response["data"]["score"]
                results["hunterio"] = hunterio_score
            else:
                results["hunterio"] = "Not found on Hunter.io"
        
        # Query ipqualityscore API
        url = f"https://www.ipqualityscore.com/api/json/email/{ipqualityscore_key}/{email}"
        response = httpx.get(url)
        if response.status_code == 200:
            ipquality_response = response.json()
            if 'fraud_score' in ipquality_response:
                ipQuality_score = ipquality_response["fraud_score"]
                results["ipqualityscore"] = ipQuality_score
            else:
                results["ipqualityscore"] = "Not found on IpQualityScore"

        return results

    except Exception as e:
        return "error"

#query_email_services('algilgil@uol.com.br')