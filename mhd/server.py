from flask import Flask
from flask import render_template
from flask import request
from email.parser import HeaderParser
from pygal.style import Style
from modules.ip_checker import query_ip_services
from modules.url_checker import query_url_services
from modules.email_checker import query_email_services
from modules.hash_verify import query_hash_services
from IPy import IP
import email
import mimetypes
import ipaddress
import dns.resolver
import time
import dateutil.parser
import re
import pygal
import geoip2.database
import argparse
import extract_msg
import hashlib
import math

app = Flask(__name__)
reader = geoip2.database.Reader(
    '%s/data/GeoLite2-Country.mmdb' % app.static_folder)

@app.context_processor
def utility_processor():
    def getCountryForIP(line):
        ipv4_address = re.compile(r"""
            \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
        ip = ipv4_address.findall(line)
        if ip:
            ip = ip[0]
            if IP(ip).iptype() == 'PUBLIC':
                try:
                    r = reader.country(ip).country
                    if r.iso_code and r.name:
                        return {
                            'iso_code': r.iso_code.lower(),
                            'country_name': r.name
                        }
                except geoip2.errors.AddressNotFoundError:
                    return {
                            'iso_code': None,
                            'country_name': None
                        }
    return dict(country=getCountryForIP)

@app.context_processor
def utility_processor():
    def duration(seconds, _maxweeks=99999999999):
        return ', '.join(
            '%d %s' % (num, unit)
            for num, unit in zip([
                (seconds // d) % m
                for d, m in (
                    (604800, _maxweeks),
                    (86400, 7), (3600, 24),
                    (60, 60), (1, 60))
            ], ['wk', 'd', 'hr', 'min', 'sec'])
            if num
        )
    return dict(duration=duration)

def dateParser(line):
    try:
        r = dateutil.parser.parse(line, fuzzy=True)
    except ValueError:
        r = re.findall('^(.*?)\s*(?:\(|utc)', line, re.I)
        if r:
            r = dateutil.parser.parse(r[0])
    return r

def getHeaderVal(h, data, rex='\s*(.*?)\n\S+:\s'):
    r = re.findall('%s:%s' % (h, rex), data, re.X | re.DOTALL | re.I)
    if r:
        return r[0].strip()
    else:
        return None

def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False
    
def check_dmarc_spf(email):
    domain = email.split('@')[-1].strip(".>")
    try:
        dmarc_query = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        for dns_data in dmarc_query:
            if 'DMARC1' in str(dns_data):
                dmarc_record = dns_data
    except dns.exception.DNSException:
        dmarc_record = "No DMARC record found for domain."

    try:
        spf_query = dns.resolver.resolve(domain, 'TXT')
        for dns_data in spf_query:
            if 'spf1' in str(dns_data):
                spf_record = dns_data
    except dns.exception.DNSException:
        spf_record = "No SPF record found for domain."

    return spf_record, dmarc_record

def display_informations(metadata, content):
    if not isinstance(content, str):
        content = str(content)
    
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ip_addresses = []
    for key, value in metadata.items():
        ip_addresses += [ip for ip in re.findall(ip_pattern, str(value)) if not is_internal_ip(ip) and ip[0] != '0']
    ip_addresses += [ip for ip in re.findall(ip_pattern, content) if not is_internal_ip(ip) and ip[0] != '0']

    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    email_addresses = []
    headers = ['Return-Path', 'From', 'To', 'CC']
    for header in headers:
        if header in metadata:
            matches = re.findall(email_pattern, str(metadata[header]))
            email_addresses.extend(matches)
    matches = re.findall(email_pattern, content)
    email_addresses.extend(matches)

    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    urls_found = []
    for key, value in metadata.items():
        urls = re.findall(url_pattern, str(value))
        urls_found += [url.strip(" >") for url in urls]
    for match in re.finditer(url_pattern, content):
        url = match.group()
        clean_url = re.sub(r'^https?://', '', url).split("/")[0].split("]")[0]
        urls_found.append(clean_url)

    ip_addresses = list(set(ip_addresses))
    email_addresses = list(set(email_addresses))
    urls_found = list(set(urls_found))
    
    return ip_addresses, email_addresses, urls_found

def get_text_bodies(message):
    bodies = []
    if isinstance(message, email.message.Message) and message.is_multipart():
        for part in message.get_payload():
            if part.get_content_type() == 'text/plain':
                bodies.append(part.get_payload(decode=True).decode())
            elif isinstance(part, email.message.Message):
                bodies.extend(get_text_bodies(part))
    elif isinstance(message, email.message.Message) and message.get_content_type() == 'text/plain':
        bodies.append(message.get_payload(decode=True).decode())
    return bodies

def get_attachments(mail_file, msg_content):
    attachments_list = []
    if mail_file.filename.endswith(".msg"):
        msg_content = extract_msg.Message(mail_file)
        attachments_list = []
        for attachment in msg_content.attachments:
            attachment_filename = attachment.longFilename
            content_type, _ = mimetypes.guess_type(attachment_filename)
            attachment_data = attachment.data
            sha256_hash = hashlib.sha256(attachment_data).hexdigest()
            md5_hash = hashlib.md5(attachment_data).hexdigest()
            size_mb = math.ceil(len(attachment_data) / (1024 * 1024))
            analysis_256 = query_hash_services(sha256_hash)
            analysis_md5 = query_hash_services(md5_hash)
            attachments = {
                "filename": attachment_filename,
                "content_type": content_type,
                "sha256": sha256_hash,
                "md5": md5_hash,
                "size_mb": size_mb,
                "HA_Analysis_256": analysis_256.get('ha'),
                "VT_Analysis_256": analysis_256.get('vt'),
                "HA_Analysis_md5": analysis_md5.get('ha'),
                "VT_Analysis_md5": analysis_md5.get('vt')
            }
            attachments_list.append(attachments)

    elif mail_file.filename.endswith(".eml"):
        attachment_parser = email.message_from_string(msg_content)
        for part in attachment_parser.walk():
            disposition = part.get("Content-Disposition")
            if disposition and disposition.startswith("attachment"):
                attachment_filename = part.get_filename()
                content_type = part.get_content_type()
                attachment_data = part.get_payload(decode=True)
                sha256_hash = hashlib.sha256(attachment_data).hexdigest()
                md5_hash = hashlib.md5(attachment_data).hexdigest()
                size_mb = math.ceil(len(attachment_data) / (1024 * 1024))
                analysis_256 = query_hash_services(sha256_hash)
                analysis_md5 = query_hash_services(md5_hash)
                attachments = {
                    "filename": attachment_filename,
                    "content_type": content_type,
                    "sha256": sha256_hash,
                    "md5": md5_hash,
                    "size_mb": size_mb,
                    "HA_Analysis_256": analysis_256.get('ha'),
                    "VT_Analysis_256": analysis_256.get('vt'),
                    "HA_Analysis_md5": analysis_md5.get('ha'),
                    "VT_Analysis_md5": analysis_md5.get('vt')
                }
                attachments_list.append(attachments)
    else:
        return "Filetype not Supported..."
    
    return attachments_list

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        mail_file = request.files['headers']
        if mail_file.filename.endswith(".msg"):
            msg_content = extract_msg.Message(mail_file)
            mail_data = msg_content.header.as_string()
            attachments_list = get_attachments(mail_file, msg_content)
            bodies = get_text_bodies(msg_content)
        elif mail_file.filename.endswith(".eml"):
            msg_content = email.message_from_bytes(mail_file.read())
            mail_data = msg_content.as_string()
            attachments_list = get_attachments(mail_file, mail_data)
            bodies = [part.get_payload() for part in msg_content.walk() if part.get_content_type() == 'text/plain']
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        received = n.get_all('Received')
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', mail_data, re.X | re.DOTALL | re.I)
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
            line = list(map(str.strip, line))
            line = [x.replace('\r\n', ' ') for x in line]
            try:
                if ';' in received[i + 1]:
                    next_line = received[i + 1].split(';')
                else:
                    next_line = received[i + 1].split('\r\n')
                next_line = list(map(str.strip, next_line))
                next_line = [x.replace('\r\n', '') for x in next_line]
            except IndexError:
                next_line = None

            org_time = dateParser(line[-1])
            if not next_line:
                next_time = org_time
            else:
                next_time = dateParser(next_line[-1])

            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)
                
            delay = (org_time - next_time).seconds
            if delay < 0:
                delay = 0

            try:
                ftime = org_time.utctimetuple()
                ftime = time.strftime('%m/%d/%Y %I:%M:%S %p', ftime)
                r[c] = {
                    'Timestmp': org_time,
                    'Time': ftime,
                    'Delay': delay,
                    'Direction': [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                }
                c -= 1
            except IndexError:
                pass

        for i in list(r.values()):
            if i['Direction'][0]:
                graph.append(["From: %s" % i['Direction'][0], i['Delay']])
            else:
                graph.append(["By: %s" % i['Direction'][1], i['Delay']])

        totalDelay = sum([x['Delay'] for x in list(r.values())])
        fTotalDelay = utility_processor()['duration'](totalDelay)
        delayed = True if totalDelay else False

        custom_style = Style(
            background='transparent',
            plot_background='transparent',
            font_family='googlefont:Open Sans',
        )
        line_chart = pygal.HorizontalBar(
            style=custom_style, height=250, legend_at_bottom=True,
            tooltip_border_radius=10)
        line_chart.tooltip_fancy_mode = False
        line_chart.title = 'Total Delay is: %s' % fTotalDelay
        line_chart.x_title = 'Delay in seconds.'
        for i in graph:
            line_chart.add(i[0], i[1])
        chart = line_chart.render(is_unicode=True)

        summary = {
            'From': n.get('From') or getHeaderVal('from', mail_data),
            'To': n.get('to') or getHeaderVal('to', mail_data),
            'Cc': n.get('cc') or getHeaderVal('cc', mail_data),
            'Subject': n.get('Subject') or getHeaderVal('Subject', mail_data),
            'MessageID': n.get('Message-ID') or getHeaderVal('Message-ID', mail_data),
            'Date': n.get('Date') or getHeaderVal('Date', mail_data),
        }

        security_headers = ['Received-SPF', 'Authentication-Results',
                            'DKIM-Signature', 'ARC-Authentication-Results']
        
        spf_record, dmarc_record = check_dmarc_spf(n.get('From') or getHeaderVal('from', mail_data))

        ip_addresses, email_addresses, urls_found = display_informations(n, bodies)

        ip_data = {}
        for ip in ip_addresses:
            ip_data[ip] = query_ip_services(ip)

        url_data = {}
        for url in urls_found:
            url_data[url] = query_url_services(url)

        email_data = {}
        for email2 in email_addresses:
            email_data[email2] = query_email_services(email2)

        return render_template(
            'index.html', data=r, delayed=delayed, summary=summary,
            n=n, chart=chart, security_headers=security_headers,spf_record=spf_record,
            dmarc_record=dmarc_record, ip_addresses=ip_addresses, email_addresses=email_addresses,
            urls_found=urls_found,  ip_data=ip_data, url_data=url_data, email_data=email_data,
            attachments=attachments_list)
    else:
        return render_template('index.html')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mail Header Analyser")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    parser.add_argument("-b", "--bind", default="127.0.0.1", type=str)
    parser.add_argument("-p", "--port", default="8080", type=int)
    args = parser.parse_args()

    app.debug = args.debug
    app.run(host=args.bind, port=args.port)
