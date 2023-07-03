<p align="center">
    <img src="https://github.com/akajhon/MailHeaderDetective/blob/main/readme/detective_big.png" alt="Mail Header Detective logo" width="250" height="250">
</p>

# MailHeaderDetective

Mail Header Detective is an email header analysis tool written in Python. It's designed to assist in the investigation of security incidents related to emails by making the analysis and gathering of information from email headers easier.

## Features

Mail Header Detective is able to:

- Analyze an email header and extract pertinent information.
- Check the reputation of the IPs found in the headers by querying various APIs such as VirusTotal, Hybrid-Analysis, Maltiverse, and PhishTank.
- Identify delays between each hop in an email's delivery by analyzing the timestamp data in the email header. This can help identify any abnormal delays or potential issues in the email delivery process.
- Trace the origin of an email. By carefully analyzing the "Received" fields in the email header, the tool is capable of identifying the IP address and consequently the server from which the email originated.
- Identify the country of origin of an email by mapping the IP address to its country. This can be particularly useful for identifying spam emails or in digital forensics investigations.
- Operate on a user interface to facilitate usage.
- Perform API integrations. MHD can identify IP addresses, email addresses, and URLs in the email metadata and send them to services such as VirusTotal, Hunter.io, Maltiverse, CheckPhish, Phishtank, and others for a detailed analysis.

In essence, the "Mail Header Detective" is a powerful tool that can aid in dissecting complex email headers, providing useful insights and valuable information about the email's journey from the sender to the recipient.

## Requirements

To run the Mail Header Detective, you need:

- Python 3.8+
- Python Packages: httpx, os, python-dotenv, concurrent.futures, dnspython, extract_msg, Flask, geoip2, IPy, maltiverse, pygal, python_dateutil, and gunicorn

## Running Locally

Clone the repository to your local machine:

```bash
git clone https://github.com/akajhon/MailHeaderDetective.git
```

Navigate to the project directory and install the necessary dependencies:

```bash
cd MailHeaderDetective
pip install -r requirements.txt
```

Run the main script:

```bash
python server.py -d
```

Access the application:

```bash
https://127.0.0.1:8080
```

## Running with Docker-Compose

Clone the repository to your local machine:

```bash
git clone https://github.com/akajhon/MailHeaderDetective.git
```

Navigate to the project directory:

```bash
cd MailHeaderDetective
```

Start the container with the command:

```bash
docker-compose up -d
```

Access the application:

```bash
https://127.0.0.1:8080
```

## API Keys

For a complete execution, it is necessary to create the .env file to store the API keys:

```bash
touch .env
```

The file should be placed inside the `mhd/modules` directory and should have the following structure:

```bash
ABUSEIPDB = <your_API_key>
IPQUALITYSCORE = <your_API_key>
VIRUSTOTAL = <your_API_key>
MALTIVERSE = <your_API_key>
HYBRIDANALYSIS = <your_API_key>
```

## Inspiration

This project was created with the intention of improving and continuing the development of the `email-header-analyzer` project, available at:

```bash
https://github.com/cyberdefenders/email-header-analyzer
```

## How to Use

To use Mail Header Detective, you need to provide the .msg or .eml file of the email you wish to analyze.

## Contributing

Contributions to the Mail Header Detective are welcome! Feel free to open an issue or submit a Pull Request.

## License

Mail Header Detective is licensed under the MIT License.

## Contact

If you have any questions or feedback, feel free to reach out through GitHub!
