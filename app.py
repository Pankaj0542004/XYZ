from flask import Flask, render_template, request
import requests

app = Flask(__name__)

def is_vulnerable(url):
    try:
        response = requests.get(url)
        if 'X-Frame-Options' in response.headers:
            if response.headers['X-Frame-Options'] == 'DENY' or response.headers['X-Frame-Options'] == 'SAMEORIGIN':
                return False
            else:
                return True
        elif 'Content-Security-Policy' in response.headers:
            if 'frame-ancestors' in response.headers['Content-Security-Policy']:
                return True
        else:
            # Check if there are frames or iframes in the HTML content
            if '<frame' in response.text.lower() or '<iframe' in response.text.lower():
                return True
        return False
    except requests.exceptions.RequestException:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_vulnerability():
    website_url = request.form['website_url']
    vulnerable = is_vulnerable(website_url)
    if vulnerable:
        return render_template('result.html', website_url=website_url, status="Vulnerable")
    else:
        return render_template('result.html', website_url=website_url, status="Not Vulnerable")

if __name__ == '__main__':
    app.run(debug=True)
