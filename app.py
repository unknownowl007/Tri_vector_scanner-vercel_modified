import io
import re
import os
import secrets
import cv2
import joblib
import hashlib
import requests
import numpy as np
from PIL import Image
from zxcvbn import zxcvbn
from flask import Flask, Response, render_template, request, jsonify
from domain_checks import (
    DomainCheckError,
    check_ssl_certificate,
    lookup_whois,
    normalize_domain,
)
from enhanced_features import extract_enhanced_features
from ip_lookup import IPLookupError, lookup_public_ip
from known_phishing import check_known_phishing_url, load_known_phishing_urls
from model_explanations import explain_random_forest
from url_analysis import analyze_redirect_chain, check_lookalike_domain

app = Flask(__name__, static_folder="public/static", static_url_path="/static")

# Load the URL classification models.
if os.environ.get("VERCEL"):
    model = None
    print("[System] Legacy model is excluded from the Vercel deployment bundle.")
else:
    try:
        model = joblib.load("model/phishing_model.pkl")
        print("[System] Phishing model loaded successfully.")
    except Exception as e:
        print(f"[System] Warning: Phishing model failed to load. {e}")
        model = None

try:
    enhanced_model = joblib.load("model/phishing_model_enhanced.pkl")
    print("[System] Enhanced phishing model loaded successfully.")
except Exception as e:
    print(f"[System] Warning: Enhanced phishing model failed to load. {e}")
    enhanced_model = None

known_phishing_urls = load_known_phishing_urls()

def extract_features(url):
    url = str(url).lower()
    brands = ['google', 'facebook', 'microsoft', 'amazon', 'apple', 'netflix', 'instagram', 'paypal', 'ebay', 'walmart', 'outlook']
    dots = url.count('.')
    subdomains = max(0, dots - 1)
    
    return [[
        len(url),                         
        dots,                             
        url.count('-'),                   
        url.count('/'),                   
        url.count('@'),                   
        url.count('?'),                   
        url.count('_') + url.count('%'),  
        subdomains,                       
        1 if "//" in url[7:] else 0,      
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0, 
        1 if url.startswith('https') else 0, 
        sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0, 
        1 if any(word in url for word in ['login', 'verify', 'bank', 'secure', 'update', 'support', 'service']) else 0, 
        1 if any(brand in url for brand in brands) else 0, 
        1 if any(url.endswith(ext) for ext in ['.php', '.html', '.aspx', '.exe']) else 0 
    ]]

def classify_url(url):
    active_model = enhanced_model if enhanced_model is not None else model
    if active_model is None:
        return {"error": "Classification engine is offline."}
    
    if active_model is enhanced_model:
        features = [extract_enhanced_features(url)]
    else:
        features = extract_features(url)
    prediction = active_model.predict(features)[0]
    prob = active_model.predict_proba(features)[0]
    confidence = round((prob[1] if prediction == 1 else prob[0]) * 100, 2)
    
    explanation = (
        explain_random_forest(active_model, features)
        if active_model is enhanced_model
        else {
            "method": "not_available",
            "signals": [],
            "note": "Detailed feature explanations are available with the enhanced model.",
        }
    )
    return {
        "url": url,
        "is_phishing": bool(prediction == 1),
        "confidence": confidence,
        "model": "enhanced" if active_model is enhanced_model else "legacy",
        "explanation": explanation,
        "known_phishing": check_known_phishing_url(url, known_phishing_urls),
    }

def decode_qr(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        cv_img = np.array(img)[:, :, ::-1].copy()
        detector = cv2.QRCodeDetector()
        url, _, _ = detector.detectAndDecode(cv_img)
        return url if url else None
    except Exception:
        return None

def check_pwned(password):
    sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
    
    try:
        res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if res.status_code == 200:
            for line in res.text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
    except requests.RequestException:
        pass
    return 0

# Application routes.
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/api/scan/url", methods=["POST"])
def api_scan_url():
    payload = request.get_json() or {}
    url = payload.get("url", "").strip()
    
    if not url:
        return jsonify({"status": "error", "message": "Missing URL payload."}), 400
    
    return jsonify({"status": "success", "data": classify_url(url)})

@app.route("/api/scan/qr", methods=["POST"])
def api_scan_qr():
    if 'qr_image' not in request.files or request.files['qr_image'].filename == '':
        return jsonify({"status": "error", "message": "Missing image payload."}), 400
    
    extracted_url = decode_qr(request.files['qr_image'].read())
    if not extracted_url:
        return jsonify({"status": "error", "message": "No decodable QR structure found."}), 400
    
    return jsonify({
        "status": "success", 
        "extracted_url": extracted_url, 
        "data": classify_url(extracted_url)
    })

@app.route("/api/check/password", methods=["POST"])
def api_check_password():
    payload = request.get_json() or {}
    pwd = payload.get("password", "")
    
    if not pwd:
        return jsonify({"status": "error", "message": "Missing password payload."}), 400
    
    analysis = zxcvbn(pwd)
    
    return jsonify({
        "status": "success",
        "score": analysis.get("score", 0),
        "warning": analysis["feedback"].get("warning", ""),
        "suggestions": analysis["feedback"].get("suggestions", []),
        "breach_count": check_pwned(pwd)
    })
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/why")
def why():
    return render_template("why.html")

@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")

@app.route("/limitations")
def limitations():
    return render_template("limitations.html")

@app.route("/future")
def future():
    return render_template("future.html")


@app.route("/history")
def history():
    return render_template("history.html")


@app.context_processor
def inject_nav():
    pages = [
        {"endpoint": "about", "label": "About Me"},
        {"endpoint": "why", "label": "Why This Project"},
        {"endpoint": "how_it_works", "label": "How This Works"},
        {"endpoint": "limitations", "label": "Limitations"},
        {"endpoint": "future", "label": "Future Plans"},
        {"endpoint": "history", "label": "Scan History"},
    ]
    keys = [p["endpoint"] for p in pages]
    ep = request.endpoint
    prev_page = next_page = None
    if ep in keys:
        i = keys.index(ep)
        prev_page = pages[i - 1] if i > 0 else None
        next_page = pages[i + 1] if i < len(pages) - 1 else None
    return {"nav_pages": pages, "prev_page": prev_page, "next_page": next_page}


@app.route("/api/scan/url/enhanced", methods=["POST"])
def api_scan_url_enhanced():
    payload = request.get_json(silent=True)
    url = payload.get("url", "").strip() if isinstance(payload, dict) else ""
    if not url:
        return jsonify({"status": "error", "message": "Missing URL payload."}), 400
    if enhanced_model is None:
        return jsonify({"status": "error", "message": "Enhanced classification engine is offline."}), 503

    features = [extract_enhanced_features(url)]
    prediction = enhanced_model.predict(features)[0]
    probabilities = enhanced_model.predict_proba(features)[0]
    confidence = round(
        (probabilities[1] if prediction == 1 else probabilities[0]) * 100,
        2,
    )
    return jsonify({
        "status": "success",
        "data": {
            "url": url,
            "is_phishing": bool(prediction == 1),
            "confidence": confidence,
            "feature_count": len(features[0]),
            "explanation": explain_random_forest(enhanced_model, features),
            "known_phishing": check_known_phishing_url(url, known_phishing_urls),
        },
    })


@app.route("/api/analyze/redirects", methods=["POST"])
def api_analyze_redirects():
    payload = request.get_json(silent=True)
    url = payload.get("url", "").strip() if isinstance(payload, dict) and isinstance(payload.get("url"), str) else ""
    if not url:
        return jsonify({"status": "error", "message": "Enter a URL to analyze."}), 400
    try:
        result = analyze_redirect_chain(url)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except DomainCheckError as error:
        return jsonify({"status": "error", "message": str(error)}), 502
    return jsonify({"status": "success", "data": result})


@app.route("/api/analyze/lookalike", methods=["POST"])
def api_analyze_lookalike():
    payload = request.get_json(silent=True)
    domain = payload.get("domain", "").strip() if isinstance(payload, dict) and isinstance(payload.get("domain"), str) else ""
    if not domain:
        return jsonify({"status": "error", "message": "Enter a domain to check."}), 400
    try:
        result = check_lookalike_domain(domain)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    return jsonify({"status": "success", "data": result})


@app.route("/api/domain/ssl", methods=["POST"])
def api_domain_ssl():
    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    try:
        hostname = normalize_domain(payload.get("domain", ""))
        result = check_ssl_certificate(hostname)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except DomainCheckError as error:
        return jsonify({"status": "error", "message": str(error)}), 502
    return jsonify({"status": "success", "data": result})


@app.route("/api/domain/whois", methods=["POST"])
def api_domain_whois():
    payload = request.get_json(silent=True)
    payload = payload if isinstance(payload, dict) else {}
    try:
        hostname = normalize_domain(payload.get("domain", ""))
        result = lookup_whois(hostname)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except DomainCheckError as error:
        return jsonify({"status": "error", "message": str(error)}), 502
    return jsonify({"status": "success", "data": result})


@app.route("/api/domain/ip-lookup", methods=["POST"])
def api_domain_ip_lookup():
    payload = request.get_json(silent=True)
    address = payload.get("ip", "").strip() if isinstance(payload, dict) and isinstance(payload.get("ip"), str) else ""
    if not address:
        return jsonify({"status": "error", "message": "Enter a public IP address to look up."}), 400
    try:
        result = lookup_public_ip(address)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    except IPLookupError as error:
        return jsonify({"status": "error", "message": str(error)}), 502
    return jsonify({"status": "success", "data": result})


SPEED_DOWNLOAD_BYTES = 4 * 1024 * 1024
SPEED_UPLOAD_LIMIT = 2 * 1024 * 1024
SPEED_DOWNLOAD_PAYLOAD = secrets.token_bytes(SPEED_DOWNLOAD_BYTES)


@app.route("/api/speed/download", methods=["GET"])
def api_speed_download():
    response = Response(
        SPEED_DOWNLOAD_PAYLOAD,
        mimetype="application/octet-stream",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Content-Length"] = str(SPEED_DOWNLOAD_BYTES)
    return response


@app.route("/api/speed/upload", methods=["POST"])
def api_speed_upload():
    if request.content_length is not None and request.content_length > SPEED_UPLOAD_LIMIT:
        return jsonify({"status": "error", "message": "Upload exceeds the 2 MB test limit."}), 413
    uploaded = request.stream.read(SPEED_UPLOAD_LIMIT + 1)
    if len(uploaded) > SPEED_UPLOAD_LIMIT:
        return jsonify({"status": "error", "message": "Upload exceeds the 2 MB test limit."}), 413
    return jsonify({"status": "success", "bytes_received": len(uploaded)})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)