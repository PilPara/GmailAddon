import requests

real_auth_results = (
    "mx.google.com;"
    " dkim=pass header.i=@comeet-notifications.com header.s=pic header.b=RfhSqodq;"
    " dkim=pass header.i=@mailgun.org header.s=mg header.b=lInAAXux;"
    " spf=pass (google.com: domain of bounce+b96971.61a741-avidaniv12=gmail.com"
    "@comeet-notifications.com designates 159.135.229.156 as permitted sender)"
    " smtp.mailfrom=bounce+b96971.61a741-Avidaniv12=gmail.com@comeet-notifications.com;"
    " dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE)"
    " header.from=upwind.comeet-notifications.com"
)

data = {
    "authResults": real_auth_results
}


r = requests.post("http://localhost:8080/analyze", json=data)
