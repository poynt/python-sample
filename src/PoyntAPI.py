#!/usr/bin/python

import requests
import logging
import httplib
import urllib
import json
import sys
import time
import rsa
import uuid
import jwt
import ConfigParser
import getopt
import random
import pprint
import time
import locale
import os


from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal
from PIL import Image, ImageDraw, ImageFont

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )
    has_crypto = True
except ImportError:
    has_crypto = False

POYNT_CONFIG = ConfigParser.ConfigParser()

def utc_timestamp():
    return timegm(datetime.utcnow().utctimetuple())

def ensure_bytes(key):
    if isinstance(key, unicode):
        key = key.encode('utf-8')

    return key

def prettyPrint(jsonObj):
    print json.dumps(jsonObj, sort_keys=True, indent=4)
    print '*' * 60

def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in
    this function because it is programmed to be pretty
    printed and may differ from the actual request.
    """
    print('{}\n{}\n{}\n\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))

class PoyntAPI:

    debug = False

    def __init__(self, apiHost, applicationId):
        self.apiHost = apiHost
        self.applicationId = applicationId
        if self.debug == True:
            httplib.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
        with open(PRIVATE_KEY_FILE, 'r') as rsa_priv_file:
            self.rsaPrivateKey = load_pem_private_key(ensure_bytes(rsa_priv_file.read()), password=None, backend=default_backend())
        with open(PUBLIC_KEY_FILE, 'r') as rsa_pub_file:
            self.rsaPublicKey = load_pem_public_key(ensure_bytes(rsa_pub_file.read()), backend=default_backend())
	with open(POYNT_PUBLIC_KEY_FILE, 'r') as rsa_poynt_pub_file:
            self.rsaPoyntPublicKey = load_pem_public_key(ensure_bytes(rsa_poynt_pub_file.read()), backend=default_backend())


#the first and foremost thing we need to do is to obtain an access token
# we do that by generating a self-signed JWT using the private-key obtained from
# the Poynt Developer Portal and POST it to token API to obtain Poynt granted
# AccessToken, TokenType and RefreshToken.
    def getAccessToken(self):
        poyntTokenUrl = self.apiHost + "/token"
        currentDatetime = datetime.utcnow()
        expiryDatetime = datetime.utcnow() + timedelta(seconds=300)
        payload = {
            'exp': expiryDatetime,
            'iat': currentDatetime,
            'iss': self.applicationId,
            'sub': self.applicationId,
            'aud': 'https://services.poynt.net',
            'jti': str(uuid.uuid4())
        }
        encodedJWT = jwt.encode(payload, self.rsaPrivateKey, algorithm='RS256')
        #print encodedJWT
        payload = {'grantType':'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion':encodedJWT}
        print "Obtaining AccessToken using self-signed JWT:"
        code, jsonObj = self._sendFormPostRequest(poyntTokenUrl, payload, {})
        #r = requests.post(poyntTokenUrl, data=payload, headers=headers)
        #prettyPrint(r.json())
        if code == requests.codes.ok:
            self.accessToken = jsonObj['accessToken']
            self.tokenType = jsonObj['tokenType']
            self.refreshToken = jsonObj['refreshToken']
            return True
        else:
            print "*** FAILED TO OBTAIN ACCESS TOKEN ***"
            return False

    def refreshAccessToken(self):
        poyntTokenUrl = self.apiHost + "/token"
        payload = {'grantType':'REFRESH_TOKEN', 'refreshToken':self.refreshToken}
        print "Refreshing AccessToken:"
        code, jsonObj = self._sendFormPostRequest(poyntTokenUrl, payload, {})
        #r = requests.post(poyntTokenUrl, data=payload, headers=headers)
        #prettyPrint(r.json())
        if code == requests.codes.ok:
            self.accessToken = jsonObj['accessToken']
            self.tokenType = jsonObj['tokenType']
            self.refreshToken = jsonObj['refreshToken']
            return True
        else:
            print "*** FAILED TO REFRESH ACCESS TOKEN ***"
            return False

    def getCatalog(self, businessId, catalogId):
        poyntCatalogUrl = self.apiHost + "/businesses/" + businessId + "/catalogs/" + catalogId
        print "Getting catalog: " + catalogId
        code, jsonObj = self._sendGetRequest(poyntCatalogUrl, {}, {})

    def addDiscount(self, businessId, catalogId):
        poyntCatalogUrl = self.apiHost + "/businesses/" + businessId + "/catalogs/" + catalogId
        jsonPatch = [
              {
                "op":"add", "path":"/availableDiscounts", "value":
                [
                  {
                    "type": "PERCENTAGE",
                    "percentage": 5.0,
                    "code": "FIVERPERCENT",
                    "scope": "ORDER",
                    "when": {
                      "repeat": "true",
                      "repeatType": "DAILY",
                      "every": [0]
                    }
                  }
                ]
              },
              {
                "op":"add", "path":"/categories/0/availableDiscounts", "value":
                [
                  {
                    "type": "FIXED",
                    "fixed": 5,
                    "code": "FIVEDOLLAR",
                    "when": {
                      "repeat": "true",
                      "repeatType": "DAILY",
                      "every": [0]
                    }
                  }
                ]
              }
            ]
        print "Updating Catalog:"
        code, jsonObj = self._sendPatchRequest(poyntCatalogUrl, json.dumps(jsonPatch), {}, {})


    def getCatalogs(self, businessId):
        poyntCatalogUrl = self.apiHost + "/businesses/" + businessId + "/catalogs"
        print "Getting all Catalogs associated with business:"
        code, jsonObj = self._sendGetRequest(poyntCatalogUrl, {}, {})
        if code == requests.codes.ok:
            print "# of Catalogs found:" + str(len(jsonObj['catalogs']))
            return jsonObj['catalogs']

    def getProducts(self, businessId):
        poyntProductUrl = self.apiHost + "/businesses/" + businessId + "/products"
        print "Getching all Products associated with business:"
        code, jsonObj = self._sendGetRequest(poyntProductUrl, {}, {})
        if code == requests.codes.ok:
            print "# of Products found:" + str(len(jsonObj['products']))

    def getTaxes(self, businessId):
        poyntTaxesUrl = self.apiHost + "/businesses/" + businessId + "/taxes"
        print "Getching all Taxes associated with business:"
        code, jsonObj = self._sendGetRequest(poyntTaxesUrl, {}, {})

    def getCustomers(self, businessId):
        poyntCustomersUrl = self.apiHost + "/businesses/" + businessId + "/customers"
        print "Getching all Customers associated with business:"
        code, jsonObj = self._sendGetRequest(poyntCustomersUrl, {}, {})

    def getHooks(self, businessId):
        poyntHooksUrl = self.apiHost + "/hooks"
        queryParameters = { 'businessId': businessId}
        print "Getching all webhook Urls associated with business:"
        code, jsonObj = self._sendGetRequest(poyntHooksUrl, queryParameters, {})

    def getBusiness(self, businessId):
        poyntBusinessUrl = self.apiHost + "/businesses/" + businessId
        print "Fetching Business information:"
        code, jsonObj = self._sendGetRequest(poyntBusinessUrl, {}, {})
        return jsonObj

    def getBusinessUsers(self, businessId):
        poyntBusinessUsersUrl = self.apiHost + "/businesses/" + businessId + "/businessUsers"
        print "Fetching Business Users:"
        code, jsonObj = self._sendGetRequest(poyntBusinessUsersUrl, {}, {})

    def registerWebhooks(self, businessId):
        poyntWebHookUrl = self.apiHost + "/hooks"
        print "Registering Webhooks:"
        hook = {
            "applicationId": self.applicationId,
            "businessId": businessId,
            "deliveryUrl": "http://a22seventhsdeux.mybluemix.net/api/v1/notification",
            "secret": "not-the-secret-you-know",
            "eventTypes":[
                "ORDER_OPENED",
                "ORDER_COMPLETED",
                "ORDER_CANCELLED",
                "ORDER_UPDATED"
            ]
        }
        code, jsonObj = self._sendPostRequest(poyntWebHookUrl, json.dumps(hook), {}, {})
        if code == requests.codes.ok or code == requests.codes.created:
            self.getHooks(businessId)

    def deleteWebhook(self, businessId, hookId):
        poyntWebHookUrl = self.apiHost + "/hooks/" + hookId
        code = self._sendDeleteRequest(poyntWebHookUrl, {})
        if code == requests.codes.no_content:
            self.getHooks(businessId)

    def createOrder(self, businessId, storeId, paid_with_cash=False):
        poyntOrderUrl = self.apiHost + "/businesses/" + businessId + "/orders"
        currentDatetime = datetime.utcnow()
        expiryDatetime = datetime.utcnow() + timedelta(seconds=300)
        order = {
          "items":[
              {
                 "status":"FULFILLED",
                 "name":"Coffee",
                 "unitOfMeasure":"EACH",
                 "unitPrice":250,
                 "quantity":1.0,
                 "tax":0,
                 "sku": "ABC123"
              },
              {
                 "status":"FULFILLED",
                 "name":"Bagel",
                 "unitOfMeasure":"EACH",
                 "unitPrice":150,
                 "quantity":1.0,
                 "tax":0,
                 "sku": "ABC122"
              },
              {
                 "status":"FULFILLED",
                 "name":"Cream Cheese",
                 "unitOfMeasure":"EACH",
                 "unitPrice":100,
                 "quantity":1.0,
                 "tax":0,
                 "sku": "ABC122"
              }
           ],
           "amounts": {
              "taxTotal":0,
              "subTotal":500,
              "discountTotal":0,
              "currency":"USD"
           },
           "context": {
              "source":"WEB",
              "businessId": businessId,
              "storeId": storeId,
              "storeDeviceId": self.applicationId
           },
           "statuses": {
              "status":"OPENED"
           },
           "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
           "updatedAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }

        if paid_with_cash:
          order['transactions'] = [
               {
                "fundingSource" : {
                  "type": "CASH"
                },
                "action": "SALE",
                "amounts": {
                  "currency": "USD",
                  "transactionAmount": 500,
                  "orderAmount": 500,
                  "tipAmount": 0,
                  "cashbackAmount": 0
                }
              }
          ]
        print "Recording a new Order:"
        code, jsonObj = self._sendPostRequest(poyntOrderUrl, json.dumps(order), {}, {})
        if code == requests.codes.ok or code == requests.codes.created:
            self.getOrder(businessId, jsonObj['id'])
            return jsonObj['id']
        else:
            return ""

    def getOrder(self, businessId, orderId):
        poyntOrderUrl = self.apiHost + "/businesses/" + businessId + "/orders/" + orderId
        print "Fetching an Order:"
        code, jsonObj = self._sendGetRequest(poyntOrderUrl, {}, {})
        return jsonObj

    def getOrders(self, businessId):
        poyntOrdersUrl = self.apiHost + "/businesses/" + businessId + "/orders"
        print "Fetching last 5 Orders updated in the last 1 month:"
        lastHourDateTime = datetime.now() +  timedelta(hours=24*30)
        headers = { 'If-Modified-Since': lastHourDateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
        queryParameters = { 'limit': 5 }
        code, jsonObj = self._sendGetRequest(poyntOrdersUrl, queryParameters, headers)

    def uploadProductCatalog(self, businessId):
        # generate a random catalog name so we don't overwrite existing ones
        # 100,000 catalogs should be more than enough ;-)
        randomNumber = random.randint(1, 100000)
        catalogName = 'TestCatalog-' + str(randomNumber)
        print "Bulk uploading product catalog:" + catalogName
        #update the test catalog with name
        with open('config/product-catalog.csv','r') as f:
            newlines = []
            for line in f.readlines():
                newlines.append(line.replace('TestCatalogName', catalogName))
        with open('config/_updated-catalog.csv', 'w') as f:
            for line in newlines:
                f.write(line)

        poyntProductsUrl = self.apiHost + "/businesses/" + businessId + "/products"
        requestId = str(uuid.uuid4())
        headers = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Poynt-Request-Id': requestId,
                    'Authorization': self.tokenType + " " + self.accessToken }
        print "\tPOST " + poyntProductsUrl
        startTime = datetime.now()
        #NOTE: we upload the modified catalog
        files = { 'productUpload': open('config/_updated-catalog.csv', 'rb')}
        req = requests.Request('POST', poyntProductsUrl, files=files, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        return r.status_code, r.text

    def sendCloudMessage(self, businessId, storeId, packageName, className, data):
        pcmUrl = self.apiHost + "/cloudMessages"
        if not packageName:
            cloudMessage = {
                "businessId": businessId,
                "storeId": storeId,
                "ttl": 500,
                "data": data
            }
        else:
            cloudMessage = {
                "businessId": businessId,
                "storeId": storeId,
                "ttl": 500,
                "recipient": {
                    "className": className,
                    "packageName": packageName
                },
                "data": data
            }
        code, jsonObj = self._sendPostRequest(pcmUrl, json.dumps(cloudMessage), {}, {})
        if code == requests.codes.accepted:
            print "Successfully sent cloud message."

    def generateReceiptImage(self, businessId, storeId):
      business = self.getBusiness(businessId)
      # let's create an order so we can use it.
      orderId = self.createOrder(businessId, storeId, paid_with_cash=True)
      order = self.getOrder(businessId, orderId)
      receipt_array = self._buildReceiptTXT(business, order)
      self._generatePNGFromString(receipt_array, "./receipt_test.png")


    def _generatePNGFromString(self, sarray, filename):

      height = 14*len(sarray)+120
      i = Image.new("RGB", (350,height), "white")
      d = ImageDraw.Draw(i)
      imagefont = ImageFont.truetype("Courier New.ttf", 12)

      row = 0
      for line in sarray:
        print line
        d.text((0,row), line.strip('\n'), font=imagefont, fill="black")
        row += 14
      i.save(open(filename, "wb"), "PNG")


    # generate a space marked up text of a receipt to use for generating a png
    def _buildReceiptTXT(self, business, order):
      createdTimeStruct = time.strptime(order['createdAt'], "%Y-%m-%dT%H:%M:%SZ")
      createdTime = datetime.fromtimestamp(time.mktime(createdTimeStruct)).strftime("%a %m/%d/%Y %I:%M %p")
      # set the local to print dollars right
      locale.setlocale(locale.LC_ALL, "")
      width = 50
      margin = 4
      rec = []

      ## header
      rec.append(" " * width)
      rec.append(" " * width)
      rec.append(" " * width)
      rec.append( business['legalName'].center(width))
      rec.append(business['address']['line1'].center(width))
      rec.append(("%s %s %s" % (business['address']['city'], business['address']['territory'], business['address']['postalCode'])).center(width))
      rec.append(('%s-%s' % (business['phone']['areaCode'], business['phone']['localPhoneNumber'])).center(width))
      rec.append(" " * width)
      rec.append(" " * width)
      rec.append("%sTIME: %s" % (" "*margin, createdTime))
      rec.append("%sOrder ID: #%s" % (" "*margin, order['id'].split("-")[0]))
      rec.append(("-" * (width-2*margin)).center(width))

      #item section
      for item in order['items']:
        item_name = item['name']
        if item['quantity'] != "":
          item_cost = "%s%s@%s" % (" "*margin, item['quantity'], locale.currency(float(item['unitPrice']) / 100.0))
        else:
          item_cost = locale.currency(float(item['unitPrice']) / 100.0)
        space_left = width - len(item_cost) - len(item_name) - 2*margin
        rec.append("%s%s%s%s" % (" "*margin, item_name, " "*space_left, item_cost))
      rec.append(("-" * (width-2*margin)).center(width))

      #totals
      subt = locale.currency(float(order['amounts']['subTotal']) / 100.0)
      tax = locale.currency(float(order['amounts']['taxTotal']) / 100.0)
      discounts = "-"+locale.currency(float(order['amounts']['discountTotal']) / 100.0)
      grandt = locale.currency(float(order['amounts']['netTotal']) / 100.0)

      space_left = width - 2*margin - len("Total") - len(subt)
      rec.append("%s%s%s%s" % (" "*margin, "Total", " "*space_left, subt))

      space_left = width - 2*margin - len("Tax") - len(tax)
      rec.append("%s%s%s%s" % (" "*margin, "Tax", " "*space_left, tax))

      space_left = width - 2*margin - len("Discounts") - len(discounts)
      rec.append("%s%s%s%s" % (" "*margin, "Discounts", " "*space_left, discounts))

      rec.append(("-" * (width-2*margin)).center(width))

      space_left = width - 2*margin - len("Grand Total") - len(grandt)
      rec.append("%s%s%s%s" % (" "*margin, "Grand Total", " "*space_left, grandt))

      # payment transaction stuff
      for txn in order['transactions']:
        funding_src = txn['fundingSource']['type']
        funding_amt = locale.currency(float(txn['amounts']['transactionAmount']) / 100.0)
        space_left = width - 2*margin - len(funding_src) - len(funding_amt)
        rec.append("%s%s%s%s" % (" "*margin, funding_src, " "*space_left, funding_amt))


      return rec



    def _sendPostRequest(self, url, payload, queryParameters, customHeaders):
        requestId = str(uuid.uuid4())
        commonHeaders = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Poynt-Request-Id': requestId,
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': self.tokenType + " " + self.accessToken}
        headers = dict(commonHeaders.items() + customHeaders.items())
        startTime = datetime.now()
        req = requests.Request('POST', url, data=payload, params=queryParameters, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        else:
            print "\tPOST " + url
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        if r.status_code == requests.codes.unauthorized:
                    print "\t Request merchant authorization by sending them to: " + self._generateAuthzUrl()
        if r.text and self.debug:
            print "\tRESPONSE JSON:"
            prettyPrint(r.json())
        if r.text:
            return r.status_code, r.json()
        else:
            return r.status_code, None

    def _sendDeleteRequest(self, url, customHeaders):
        requestId = str(uuid.uuid4())
        commonHeaders = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Poynt-Request-Id': requestId,
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': self.tokenType + " " + self.accessToken}
        headers = dict(commonHeaders.items() + customHeaders.items())
        startTime = datetime.now()
        req = requests.Request('DELETE', url, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        else:
            print "\tDELETE " + url
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        return r.status_code

    def _sendPatchRequest(self, url, payload, queryParameters, customHeaders):
        requestId = str(uuid.uuid4())
        commonHeaders = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Poynt-Request-Id': requestId,
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Authorization': self.tokenType + " " + self.accessToken}
        headers = dict(commonHeaders.items() + customHeaders.items())
        startTime = datetime.now()
        req = requests.Request('PATCH', url, data=payload, params=queryParameters, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        else:
            print "\tPOST " + url
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        if self.debug == True:
            print "\tRESPONSE JSON:"
            prettyPrint(r.json())
        return r.status_code, r.json()

    def _sendFormPostRequest(self, url, payload, customHeaders):
        requestId = str(uuid.uuid4())
        commonHeaders = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Poynt-Request-Id': requestId }
        headers = dict(commonHeaders.items() + customHeaders.items())
        startTime = datetime.now()
        req = requests.Request('POST', url, data=payload, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        else:
            print "\tPOST " + url
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        if self.debug == True:
            print "\tRESPONSE JSON:"
            prettyPrint(r.json())
        if r.status_code == 401:
            print "\t Request merchant authorization by sending them to: " + self._generateAuthzUrl()
        return r.status_code, r.json()

#requests status codes: https://github.com/kennethreitz/requests/blob/master/requests/status_codes.py
    def _sendGetRequest(self, url, queryParameters, customHeaders):
        commonHeaders = { 'api-version':POYNT_API_VERSION,
                    "User-Agent": 'PoyntSample-Python',
                    'Authorization': self.tokenType + " " + self.accessToken }
        headers = dict(commonHeaders.items() + customHeaders.items())
        startTime = datetime.now()
        req = requests.Request('GET', url, params=queryParameters, headers=headers)
        prepared = req.prepare()
        if self.debug == True:
            pretty_print_POST(prepared)
        else:
            print "\tGET " + url
        s = requests.Session()
        r = s.send(prepared)
        endTime = datetime.now()
        delta = endTime - startTime
        print "\tHTTP RESPONSE CODE:" + str(r.status_code)
        print "\tRESPONSE TIME: " + str(delta.total_seconds() * 1000) + " msecs"
        if self.debug == True:
            print "\tRESPONSE JSON:"
            prettyPrint(r.json())
        if r.status_code == requests.codes.unauthorized:
            print "\t Request merchant authorization by sending them to: " + self._generateAuthzUrl()

        if r.status_code == requests.codes.not_modified:
            print "\t Order not modified since given if-modified-since time"
            return r.status_code, {} 
        else:
            return r.status_code, r.json()

    def _generateAuthzUrl(self):
        poyntAuthzUrl = POYNT_AUTHZ_HOST_URL + "/applications/authorize?"
        params = { 'applicationId' : self.applicationId,
                    'callback' : 'https://your-site.com/update-this-url',
                    'context' : 'python-test-script'
                    }
        return poyntAuthzUrl + urllib.urlencode(params)
    # jwt.decode verifies JWT signature and fails with jwt.exceptions.DecodeError if signature is invalid
    def verifyJwtSignature(self):
        claims=jwt.decode(self.accessToken, self.rsaPoyntPublicKey,algorithms=['RS256'],audience=self.applicationId)
        print (claims)


def main(argv):
    base_dir=os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0])))

    global POYNT_ENV, POYNT_API_HOST_URL, POYNT_API_VERSION, POYNT_AUTHZ_HOST_URL
    global BUSINESS_ID, APPLICATION_ID, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, POYNT_PUBLIC_KEY_FILE, DEBUG

    POYNT_ENV = 'LIVE'
    DEBUG = False

    try:
        opts, args = getopt.getopt(argv,"he:v",['env=', 'verbose'])
    except getopt.GetoptError:
        print 'PoyntAPI.py -e < CI or LIVE > -v'
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print 'PoyntAPI.py -e < CI or LIVE > -v'
            sys.exit()
        elif opt in ('-e', '--env'):
            POYNT_ENV = arg.upper()
        elif opt in ('-v', '--verbose'):
            DEBUG = True

    print "Executing APIs in ", POYNT_ENV
    POYNT_CONFIG.read(base_dir + '/config/poynt.ini')
    ### POYNT API URL and VERSION, Application settings
    POYNT_API_HOST_URL = POYNT_CONFIG.get(POYNT_ENV,'POYNT_API_HOST_URL')
    POYNT_API_VERSION = POYNT_CONFIG.get(POYNT_ENV,'POYNT_API_VERSION')
    POYNT_AUTHZ_HOST_URL = POYNT_CONFIG.get(POYNT_ENV,'POYNT_AUTHZ_HOST_URL')
    BUSINESS_ID = POYNT_CONFIG.get(POYNT_ENV,'BUSINESS_ID')
    STORE_ID = POYNT_CONFIG.get(POYNT_ENV,'STORE_ID')
    APPLICATION_ID = POYNT_CONFIG.get(POYNT_ENV,'APPLICATION_ID')
    PRIVATE_KEY_FILE = base_dir + '/' + POYNT_CONFIG.get(POYNT_ENV,'PRIVATE_KEY_FILE')
    PUBLIC_KEY_FILE = base_dir + '/' + POYNT_CONFIG.get(POYNT_ENV,'PUBLIC_KEY_FILE')
    POYNT_PUBLIC_KEY_FILE = base_dir + '/' + POYNT_CONFIG.get(POYNT_ENV,'POYNT_PUBLIC_KEY_FILE')

    if(has_crypto):
        poyntAPI = PoyntAPI(POYNT_API_HOST_URL, APPLICATION_ID)
        if DEBUG == True:
            poyntAPI.debug = DEBUG
        if poyntAPI.getAccessToken() == True:
            #catalogs = poyntAPI.getCatalogs(BUSINESS_ID)
            #if catalogs != None:
            #    for catalog in catalogs:
            #        poyntAPI.getCatalog(BUSINESS_ID, catalog["id"])
                #add a discount to one of the catalog
                #poyntAPI.addDiscount(BUSINESS_ID, catalogs[0]["id"])
                #get catalog to check if it's added
                #poyntAPI.getCatalog(BUSINESS_ID, catalogs[0]["id"])
            #poyntAPI.uploadProductCatalog(BUSINESS_ID)
            #poyntAPI.getProducts(BUSINESS_ID)
            #poyntAPI.getTaxes(BUSINESS_ID)
            #poyntAPI.getCustomers(BUSINESS_ID)
            #poyntAPI.getHooks(BUSINESS_ID)
            #poyntAPI.getBusiness(BUSINESS_ID)
            #poyntAPI.getBusinessUsers(BUSINESS_ID)
            poyntAPI.createOrder(BUSINESS_ID, STORE_ID)
            #poyntAPI.getOrders(BUSINESS_ID)
            #poyntAPI.refreshAccessToken()
            #poyntAPI.registerWebhooks(BUSINESS_ID)
            #poyntAPI.generateReceiptImage(BUSINESS_ID, STORE_ID)
            ## delete webhook to mark the hook as inactive (note that this doesn't delete the hook just changes it's state)
            #poyntAPI.deleteWebhook(BUSINESS_ID, "525721fb-3e66-4394-a266-4075c7630ee9")
            #poyntAPI.sendCloudMessage(BUSINESS_ID, STORE_ID, "com.my.android.package", "com.my.android.package.MyBroadcastReceiverClass", "Hello from the cloud.")
            #poyntAPI.sendCloudMessage(BUSINESS_ID, STORE_ID, "", "", "{\"action\":\"authorize\", \"purchaseAmount\": 1000, \"tipAmount\": 100, \"currency\":\"USD\", \"referenceId\":\"ABC1234\", \"orderId\":\"hello-order-id\", \"callbackUrl\":\"http%3A%2F%2Frequestb.in%2F11odyf81\"}")
            #poyntAPI.sendCloudMessage(BUSINESS_ID, STORE_ID, "", "", "{\"action\":\"sale\", \"purchaseAmount\": 1000, \"tipAmount\": 100, \"currency\":\"USD\", \"referenceId\":\"ABC1234\", \"callbackUrl\":\"http%3A%2F%2Frequestb.in%2F11odyf81\"}")
            #poyntAPI.sendCloudMessage(BUSINESS_ID, STORE_ID, "", "", "{\"action\":\"non-reference-credit\", \"purchaseAmount\": 1000, \"tipAmount\": 100, \"currency\":\"USD\", \"referenceId\":\"ABC1234\", \"callbackUrl\":\"http%3A%2F%2Frequestb.in%2F11odyf81\"}")
            #poyntAPI.sendCloudMessage(BUSINESS_ID, STORE_ID, "", "", "{\"action\":\"refund\", \"transactionId\":\"{transactionId}\",\"referenceId\":\"ABC1234\", \"callbackUrl\":\"http%3A%2F%2Frequestb.in%2F11odyf81\"}")
	    #poyntAPI.verifyJwtSignature()
        else:
            print "Cannot continue without an AccessToken!"
    else:
        print '\'cryptography\' package is required!'

if __name__ == "__main__":
    main(sys.argv[1:])
