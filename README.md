# Site-Analyzer
Flask-based application that conducts site analysis


After starting the Flask application, it accepts a URL as input and return the following information: 

* Domain Information
  * Server IP
  * Location (Country)
  * ASN
  * ISP
  * Organization
* Subdomain Information
* List of external domains from which 
  * Style sheets are being fetched
  * Javascripts are being fetched.
  * Images are being fetched.
  * Iframe sources
  * Anchor tag references (a hrefs)
	

Input: The URL of the website will be passed in the parameter, i.e.:\
http://127.0.0.1/?url=https://www.reddit.com 
