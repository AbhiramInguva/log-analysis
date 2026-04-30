from flask import Flask, render_template, jsonify
import requests
import json

from Detection import detection, brute_map

app = Flask(__name__)

with open('config.json', 'r') as config_file:
    config = json.load(config_file)

geo_cache = {}

MOCK_GEO = {
    "10.0.0.5":  {"lat": 55.7558, "lon": 37.6173, "city": "Moscow",      "country": "Russia"},
    "10.0.0.7":  {"lat": 39.9042, "lon": 116.4074, "city": "Beijing",    "country": "China"},
    "10.0.0.9":  {"lat": 37.5665, "lon": 126.9780, "city": "Seoul",      "country": "South Korea"},
    "10.0.0.11": {"lat": 52.5200, "lon": 13.4050,  "city": "Berlin",     "country": "Germany"},
    "10.0.0.13": {"lat": 41.9028, "lon": 12.4964,  "city": "Rome",       "country": "Italy"},
    "10.0.0.15": {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo",      "country": "Japan"},
    "172.26.186.170": {"lat": 17.3850, "lon": 78.4867, "city": "Hyderabad", "country": "India"},
}

def get_geolocation(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if ip in MOCK_GEO:
        geo_cache[ip] = MOCK_GEO[ip]
        return geo_cache[ip]
    try:
        url = f"{config['geo_api_url']}{ip}"
        response = requests.get(url).json()
        if response['status'] == 'success':
            geo_cache[ip] = {
                'lat': response['lat'],
                'lon': response['lon'],
                'city': response['city'],
                'country': response['country']
            }
            return geo_cache[ip]
    except Exception as e:
        print(f"Error locating {ip}: {e}")
    return None

@app.route('/')
def index():
    return render_template('map.html')

@app.route('/api/threats')
def get_threats():
    threats = []
    for entry in detection:
        ip, agent, method, timestamp, rule = entry
        geo = get_geolocation(ip)
        if geo:
            threats.append({
                "ip": ip,
                "rule": rule,
                "lat": geo['lat'],
                "lon": geo['lon'],
                "location": f"{geo['city']}, {geo['country']}"
            })
    for ip, data in brute_map.items():
        first_seen, count, last_seen, code, agent = data
        duration = (last_seen - first_seen).total_seconds()
        if count > 5 and duration <= 60 and code == "401":
            geo = get_geolocation(ip)
            if geo:
                threats.append({
                    "ip": ip,
                    "rule": "Brute Force",
                    "lat": geo['lat'],
                    "lon": geo['lon'],
                    "location": f"{geo['city']}, {geo['country']}"
                })
    return jsonify(threats)

if __name__ == '__main__':
    app.run(debug=True, port=config['flask_port'])
