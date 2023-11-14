import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
import requests
from tldextract import TLDExtract
import sublist3r

app = Flask(__name__)

@app.route('/')
def analyze_website():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "Please provide a valid URL."})
    try:
        domain_info = extract_domain_info(url)
        subdomain_info = enumerate_subdomains(url)
        website_info = extract_information(url)
        result = {
            "info": domain_info["info"], 
                  "subdomains": subdomain_info["subdomains"],
                  "asset_domains": website_info["asset_domains"]}
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"})


def extract_domain_info(url):
    try:
        domain_info = TLDExtract(include_psl_private_domains=True)(url)
        ip = socket.gethostbyname(domain_info.domain + "." + domain_info.suffix)
        ipwhois_response = requests.get(f"http://ipwho.is/{ip}", timeout=20)
        ipwhois_data = ipwhois_response.json()
        isp = ipwhois_data.get("connection", {}).get('isp', 'Unknown isp')
        organization = ipwhois_data.get("connection", {}).get('org', 'Unknown organisation')
        asn = ipwhois_data.get("connection", {}).get('asn', 'Unknown asn')
        location = ipwhois_data.get("country_code", "Unknown location")

        result = {
            "info":{
                "ip":ip,
                "isp": isp,
                "organization": organization,
                "asn": asn,
                "location": location
            }
        }
        return result

    except Exception as e:
        return {"error": str(e)}


def enumerate_subdomains(url):
    domain_info = TLDExtract(include_psl_private_domains=True)(url)
    domain = domain_info.domain + "." + domain_info.suffix
    subdomains = sublist3r.main(domain, 
                                40, savefile=None, ports=None,
                                  silent=False, verbose=False, 
                                  enable_bruteforce=False, engines=None)
    return {
        "subdomains": subdomains
    }


def extract_information(url):
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            bs = BeautifulSoup(response.text, 'html.parser')
            
            asset_domains = {
                "javascripts": [],
                "stylesheets": [],
                "images": [],
                "iframes": [],
                "anchors": []
            }

            for link in bs.find_all('link', rel='stylesheet', href=True):
                href = link['href']
                if href and href.startswith('http'):
                    domain = urlparse(href).netloc  
                    asset_domains["stylesheets"].append(domain)

            for element in bs.find_all(['script', 'img', 'iframe', 'a']):
                if 'src' in element.attrs:
                    src = element['src']
                    if src and src.startswith('http'):
                        domain = urlparse(src).netloc
                        if src.endswith('.js'):
                            if(domain not in asset_domains['javascripts']):
                                asset_domains["javascripts"].append(domain)
                        elif src.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                            if(domain not in asset_domains['images']):
                                asset_domains["images"].append(domain)
                        elif '.html' in src:
                            if(domain not in asset_domains['iframes']):
                                asset_domains["iframes"].append(domain)
                if element.name == 'a':
                    href = element.get('href')
                    if href and href.startswith('http'):
                        domain = urlparse(href).netloc
                        asset_domains["anchors"].append(domain)

            print(asset_domains)
            return {
                "asset_domains": asset_domains
            }
        else:
            return {"error": "Unable to GET site."}

    except Exception as e:
         return {"error": str(e)}


if __name__ == '__main__':
    app.run(debug=True)