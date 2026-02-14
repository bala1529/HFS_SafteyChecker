from flask import Flask, render_template, request
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# 🔑 Put your new VirusTotal API key here
VT_API_KEY = "8ebfa8eb5f2c72217d87a39a95d733a490c7cb5a493923de6c317a47ca5d3dbd"

blacklist = ["malicious-site.com", "phishing-test.xyz"]

trusted_domains = [
    "google.com","youtube.com","amazon.com","amazon.in",
    "facebook.com","instagram.com","whatsapp.com","wa.me",
    "twitter.com","x.com","microsoft.com","apple.com"
]

shorteners = ["bit.ly","tinyurl.com","goo.gl"]


# ---------- VirusTotal ----------
def get_vt_domain_info(domain):

    owner = "Not Public"
    age = "Not Available"
    vt_status = "Not Checked"
    malicious_count = 0

    try:
        headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        r = requests.get(vt_url, headers=headers, timeout=10)

        if r.status_code != 200:
            return owner, age, "VT Not Available", 0

        data = r.json()

        if "data" in data:
            attrs = data["data"]["attributes"]

            owner = attrs.get("registrar", owner)

            if "creation_date" in attrs:
                creation = datetime.fromtimestamp(attrs["creation_date"])
                age_days = (datetime.now() - creation).days
                age = f"{age_days//365} years ({age_days} days)"

            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            if malicious_count > 0:
                vt_status = f"⚠ Flagged ({malicious_count} engines)"
            else:
                vt_status = "Clean"

        return owner, age, vt_status, malicious_count

    except:
        return owner, age, "VT Failed", 0


# ---------- Main URL Check ----------
def check_url(url):

    if not url.startswith("http"):
        url = "https://" + url

    score = 60
    status = "Safe"
    owner = "N/A"
    age = "N/A"
    vt_status = "Not Checked"
    malicious_count = 0

    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0].lower().replace("www.", "")

    try:
        response = requests.get(url, timeout=5)
    except:
        return "Not Found", 0, owner, age, domain, vt_status

    # HTTPS
    if parsed.scheme == "https":
        score += 10
    else:
        score -= 20

    # WHOIS
    try:
        domain_info = whois.whois(domain)

        if domain_info.org:
            owner = domain_info.org
        elif domain_info.registrar:
            owner = domain_info.registrar

        creation = domain_info.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            age_days = (datetime.now() - creation).days
            age = f"{age_days//365} years ({age_days} days)"

    except:
        pass

    # Always call VirusTotal
    vt_owner, vt_age, vt_status, malicious_count = get_vt_domain_info(domain)

    if owner == "N/A" or owner == "Privacy Protected":
        owner = vt_owner

    if age == "N/A" or age == "Not Available":
        age = vt_age

    # 🔥 Ignore false positives for trusted domains
    is_trusted = any(t in domain for t in trusted_domains)

    if malicious_count > 0 and not is_trusted:
        score -= 40
    elif malicious_count > 0 and is_trusted:
        vt_status = "Trusted Domain (False Positive Ignored)"

    # Trusted boost
    if is_trusted:
        score += 30
        if score < 85:
            score = 85

    # Final classification
    if score >= 85:
        status = "Safe"
    elif score >= 70:
        status = "Low Risk"
    elif score >= 45:
        status = "Suspicious"
    else:
        status = "Dangerous"

    return status, score, owner, age, domain, vt_status


@app.route("/", methods=["GET","POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        result = check_url(url)
    return render_template("index.html", result=result)


if __name__ == "__main__":

    app.run()
