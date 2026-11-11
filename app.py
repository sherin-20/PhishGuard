from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)

def check_url(url):
    result = []
    score = 0

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"] or not parsed.hostname:
            return {"error": "Invalid URL. Enter a valid HTTP or HTTPS URL."}

        if parsed.scheme != "https":
            score += 20
            result.append("HTTPS is not used")

        hostname = parsed.hostname

        try:
            ipaddress.ip_address(hostname)
            score += 30
            result.append("IP address used in URL")
        except ValueError:
            result.append("No IP address detected")

        keywords = ["login", "verify", "bank", "password",
                    "account", "secure", "update"]

        found = [word for word in keywords if word in url.lower()]

        if found:
            score += 30
            result.append("Suspicious keywords: " + ", ".join(found))
        else:
            result.append("No listed suspicious keywords found")

        score = min(score, 100)

        return {
            "score": score,
            "status": "Suspicious indicators found" if score >= 30 else "Fewer suspicious indicators",
            "details": result
        }

    except Exception:
        return {"error": "Unable to analyse this URL"}

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        result = check_url(url)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
