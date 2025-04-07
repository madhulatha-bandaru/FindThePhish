import pandas as pd
import numpy as np
import sys
import re
from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
from datetime import datetime
import ipaddress
import whois
import urllib
import urllib.request
import tldextract
import pickle

class FeatureExtract:
    def __init__(self):
        pass

    def rank(self, url):
        try:
            url = urllib.parse.quote(url)
            rank = BeautifulSoup(urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&url=" + url).read(), "xml").find("REACH")['RANK']
            rank = int(rank)
        except (TypeError, Exception):
            return 1
        return 0 if rank < 100000 else 1

    def isIP(self, url):
        try:
            ipaddress.ip_address(url)
            return 1
        except:
            return 0

    def isValid(self, domain_name):
        try:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            
            if isinstance(creation_date, str) or isinstance(expiration_date, str):
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            
            if not creation_date or not expiration_date:
                return 1
                
            ageofdomain = abs((expiration_date - creation_date).days)
            return 1 if (ageofdomain/30) < 6 else 0
        except:
            return 1

    def domain_reg_len(self, domain_name):
        try:
            expiration_date = domain_name.expiration_date
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            
            if not expiration_date:
                return 1
                
            today = datetime.now()
            end = abs((expiration_date - today).days)
            return 0 if (end/30) < 6 else 1
        except:
            return 1

    def isat(self, url):
        return 1 if "@" in url else 0

    def isRedirect(self, url):
        pos = url.rfind('//')
        return 1 if pos > 6 else 0

    def haveDash(self, url):
        return 1 if '-' in urlparse(url).netloc else 0

    def no_sub_domain(self, url):
        url = str(url).replace("www.", "").replace("."+tldextract.extract(url).suffix, "")
        return 0 if url.count(".") == 1 else 1

    def httpDomain(self, url):
        return 1 if 'http' in urlparse(url).netloc else 0

    def LongURL(self, url):
        return 0 if len(url) < 54 else 1

    def tinyURL(self, url):
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
        return 1 if re.search(shortening_services, url) else 0
        

class PredictURL(FeatureExtract):
    def __init__(self):
        super().__init__()

    def predict(self, url):
        feature = []
        dns = 0
        
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
       
        # Domain based features
        # feature.append(self.rank(url))
        # feature.append(1 if dns == 1 else self.isValid(domain_name))
        # feature.append(1 if dns == 1 else self.domain_reg_len(domain_name))

        # Address bar based features
        feature.append(self.isIP(url))
        feature.append(1 if dns == 1 else self.isValid(domain_name))
        feature.append(1 if dns == 1 else self.domain_reg_len(domain_name))
        feature.append(self.isat(url))
        feature.append(self.isRedirect(url))
        feature.append(self.haveDash(url))
        feature.append(self.no_sub_domain(url))
        # feature.append(self.httpDomain(url))
        feature.append(self.LongURL(url))
        feature.append(self.tinyURL(url))
        
        return self.classify(np.array(feature).reshape((1, -1)))

    def classify(self, features):
        try:
            with open('my_phishing_model.pkl', 'rb') as pick_file:
                model = pickle.load(pick_file)
            result = model.predict(features)
            return "Legitimate website" if result == 0 else "Phishing website"
        except Exception as e:
            return f"Error in classification: {str(e)}"

if __name__ == "__main__":
    extractor = PredictURL()
    print(extractor.predict("https://www.google.com"))