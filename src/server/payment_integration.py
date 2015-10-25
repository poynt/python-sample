from flask import Flask
from flask import request
import urllib
import urllib2
app = Flask(__name__)
app.debug = True

APPLICATION_ID = "urn:aid:b32fb540-e730-42b9-9b1d-c131087d1dcd"
url = "http://services.poynt.net/cloudMessages"

@app.route("/")
def default():
    return "simple payment fragment integration"


@app.route("/launch_payment", methods=['GET', 'POST'])
def launch_payment():
    #if request.method == 'GET':
    #    return "use this url to post yoru payment launch request"
    #if request.method != "POST":
    #    return "somethign is wrong with the method"

    # take in: amount, currency, and jwt
    #amount = request.form['amount']
    #currency = request.form['currency']
    #jwt = request.form['jwt']

    amount = "5.00"
    currency="USD"
    jwt = "BEARER eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1cm46YWlkOjg3OGVjMDRiLTMwOTYtNGJhNC1iYzk3LTRjZGVmOGE2YTA1OCIsImF1ZCI6InVybjphaWQ6ODc4ZWMwNGItMzA5Ni00YmE0LWJjOTctNGNkZWY4YTZhMDU4IiwicG95bnQuc2N0IjoiSiIsInBveW50Lm9yZyI6IjdkZWUxMTI1LWQ2NjEtNGJmNi05MjM5LTg3OGE3ZTQ4MWQ0YiIsImlzcyI6Imh0dHBzOlwvXC9zZXJ2aWNlcy5wb3ludC5uZXQiLCJwb3ludC5raWQiOjExMjI2NTg1MzIwMDU3Mjg4LCJleHAiOjE0NDU4MzYwNTMsImlhdCI6MTQ0NTc0OTY1MywianRpIjoiYjNiYjU5MjctZjFjMy00MGNhLWE5MTgtMmU4YTc5NDRiZjc0In0.LdGHZRQw5pPPcta_GauLExE6OFwhgOsKNV37r1fWnfY9pLON91XFcL_Ed5DjOU5nJhaEUAjU6P__xqHqlu_zMhcMZHma0nhU9TSUlRovZ0NyI6dyR2Bwwfnvzhm415fUsPozsE2hrtpeP33OU_yHYLV_AtxPdpFWyvpzPfIovOEN7oyOVKmID0hhYNwKUt2SFqZ_M5irIwgMjQqNlor-NQuTFXadnGhRo7c1G9a-_bb2Sp0SOpkUjq0dkGKYUvN-gjmkJELldnng5180R4KDdaWrb-_ktiDsHEqbIWzOXmq9_ChB8L_RQORv_aZmuhrrZ6F5BKqzTo9a5u5lDkw1-A"


    form_dict = {
                    "ttl": 500,
                    "serialNumber": "P61SHT361FS000141",
                    "storeId":
                    "abc87b3d-5d1f-4857-818b-f1992455dbaa",
                    "data":
                        {
                            "action":"authorize",
                            "purchaseAmount": amount,
                            "tipAmount": 0,
                            "currency":currency,
                            "referenceId":"ABC1234",
                            "orderId":"hello-order-id",
                            "callbackUrl":"http://192.168.1.3:5000/callback"
                        },
                    "businessId": "b51ab636-fe82-4286-bbd3-8ee73a7c922f"
                }

    data = urllib.urlencode(form_dict)
    req = urllib2.Request(url, data)
    req.add_header("Authorization", jwt)
    iresponse = urllib2.urlopen(req)
    the_page = response.read()
    return the_page


@app.route("/cloudMessages", methods=['GET', 'POST'])
def cloudMessages():
    app.logger.debug(str(request.form))
    return ""


@app.route("/callback", methods=['GET', 'POST'])
def callback():
    return "helo"



if __name__ == "__main__":
    app.run()