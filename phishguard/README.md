# PhishGuard - Phishing & Scam Detection Web App

Local Flask app that scores emails, messages and URLs for phishing risk (0-100).
Everything runs on your computer. No external APIs. Submitted URLs are **never visited**.

## Setup in VS Code (Windows)
Open the folder in VS Code, then open a terminal (Ctrl + `) and run:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```
macOS/Linux: use `source venv/bin/activate` instead of `venv\Scripts\activate`.

Open **http://127.0.0.1:5000** in your browser.

## Project structure
```
app.py           Flask routes, input validation, error pages
detector.py      ML model (TF-IDF + Logistic Regression) + keyword/pattern analysis
url_detector.py  Static URL feature analysis (string parsing only)
risk_engine.py   Combines scores -> 0-100 risk + classification
database.py      SQLite (database/phishguard.db), parameterized queries
train_model.py   Trains the model and saves model/phishing_model.joblib
templates/       HTML pages (Jinja2, auto-escaped)
static/          CSS + JavaScript
```

## How it works
1. **Frontend** - You paste text or a URL on the homepage; JavaScript validates it and submits the form.
2. **Flask** (`app.py`) - `/scan` checks type, emptiness and length, then calls the risk engine.
3. **Detection**
   - `detector.py`: the saved TF-IDF + Logistic Regression model returns a phishing probability (ML score) and regex rules find urgency words, money, shorteners, IP links, etc. (keyword score). Links inside messages are extracted as text.
   - `url_detector.py`: checks length, IP host, `@`, dots, hyphens, subdomains, ports, `%` encoding, HTTPS, punycode, TLD, shorteners and brand impersonation (URL score).
4. **Risk Engine** (`risk_engine.py`) - weighted combination:
   - Message with links: 50% ML + 25% keywords + 25% URL
   - Message without links: 60% ML + 40% keywords
   - URL only: 80% URL + 20% keywords
   - 0-29 Low Risk, 30-59 Suspicious, 60-100 High Risk, plus a list of reasons.
5. **SQLite** (`database.py`) - each scan is saved with `?` placeholders; History and Dashboard read from the same table.

## Security notes
- User input is never executed, evaluated, fetched or opened.
- Templates auto-escape output (prevents XSS); SQL uses parameters (prevents SQL injection).
- Input length limits + 64 KB request limit; errors show friendly pages.
- The training dataset is small and for learning purposes - do not rely on it as a real security product.
