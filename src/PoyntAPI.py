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


from calendar import timegm
from datetime import datetime, timedelta
from decimal import Decimal

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
            'aud': 'services.poynt.net',
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

    def getCatalogs(self, businessId):
        poyntCatalogUrl = self.apiHost + "/businesses/" + businessId + "/catalogs"
        print "Getching all Catalogs associated with business:"
        code, jsonObj = self._sendGetRequest(poyntCatalogUrl, {}, {})
        if code == requests.codes.ok:
            print "# of Catalogs found:" + str(len(jsonObj['catalogs']))

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

    def getBusinessUsers(self, businessId):
        poyntBusinessUsersUrl = self.apiHost + "/businesses/" + businessId + "/businessUsers"
        print "Fetching Business Users:"
        code, jsonObj = self._sendGetRequest(poyntBusinessUsersUrl, {}, {})

    def createOrder(self, businessId, storeId):
        poyntOrderUrl = self.apiHost + "/businesses/" + businessId + "/orders"
        currentDatetime = datetime.utcnow()
        expiryDatetime = datetime.utcnow() + timedelta(seconds=300)
        order = {
            "items":[
              {
                 "status":"ORDERED",
                 "name":"Croissant",
                 "unitOfMeasure":"EACH",
                 "unitPrice":195,
                 "tax":32,
                 "discount":20,
                 "quantity":2.0,
                 "discounts":[
                    {
                       "customName":"item-on-sale",
                       "amount":5
                    },
                    {
                       "customName":"buy 2, get 15 cents off",
                       "amount":15
                    }
                 ]
              },
              {
                 "status":"ORDERED",
                 "name":"Sparkling Water",
                 "unitOfMeasure":"EACH",
                 "unitPrice":425,
                 "tax":35,
                 "quantity":1.0
              },
              {
                 "status":"ORDERED",
                 "name":"Green Tea",
                 "unitOfMeasure":"EACH",
                 "unitPrice":350,
                 "tax":28,
                 "quantity":1.0
              },
              {
                 "status":"ORDERED",
                 "name":"Coconut Water",
                 "unitOfMeasure":"EACH",
                 "unitPrice":550,
                 "tax":45,
                 "quantity":1.0
              },
              {
                 "status":"ORDERED",
                 "name":"Coffee",
                 "unitOfMeasure":"EACH",
                 "unitPrice":250,
                 "tax":20,
                 "quantity":1.0
              },
              {
                 "status":"ORDERED",
                 "name":"Latte",
                 "unitOfMeasure":"EACH",
                 "unitPrice":415,
                 "tax":34,
                 "quantity":1.0
              }
           ],
           "discounts":[
              {
                 "customName":"Special discount 1",
                 "amount":50
              },
              {
                 "customName":"Repeat Customer discount",
                 "amount":30
              }
           ],
           "amounts": {
              "taxTotal":194,
              "subTotal":2380,
              "discountTotal":-100,
              "currency":"USD"
           },
           "context": {
              "source":"WEB",
              "businessId": businessId,
              "storeDeviceId": self.applicationId,
              "storeId": storeId
           },
           "statuses": {
              "status":"OPENED"
           },
           "createdAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
           "updatedAt": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        }
        print "Recording a new Order:"
        code, jsonObj = self._sendPostRequest(poyntOrderUrl, json.dumps(order), {}, {})
        if code == requests.codes.ok or code == requests.codes.created:
            self.getOrder(businessId, jsonObj['id'])

    def getOrder(self, businessId, orderId):
        poyntOrderUrl = self.apiHost + "/businesses/" + businessId + "/orders/" + orderId
        headers = { 'If-Modified-Since': datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ") }
        print "Fetching an Order:"
        code, jsonObj = self._sendGetRequest(poyntOrderUrl, {}, headers)

    def getOrders(self, businessId):
        poyntOrdersUrl = self.apiHost + "/businesses/" + businessId + "/orders"
        print "Fetching last 5 Orders:"
        queryParameters = { 'limit': 5 }
        code, jsonObj = self._sendGetRequest(poyntOrdersUrl, queryParameters, {})

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
        if r.status_code == requests.codes.unauthorized:
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
        return r.status_code, r.json()

    def _generateAuthzUrl(self):
        poyntAuthzUrl = POYNT_AUTHZ_HOST_URL + "/applications/authorize?"
        params = { 'applicationId' : self.applicationId,
                    'callback' : 'http://alavilli.com/dump.php',
                    'context' : 'python-test-script'
                    }
        return poyntAuthzUrl + urllib.urlencode(params)


def main(argv):

    global POYNT_ENV, POYNT_API_HOST_URL, POYNT_API_VERSION, POYNT_AUTHZ_HOST_URL
    global BUSINESS_ID, APPLICATION_ID, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, DEBUG

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
    POYNT_CONFIG.read('config/poynt.ini')
    ### POYNT API URL and VERSION, Application settings
    POYNT_API_HOST_URL = POYNT_CONFIG.get(POYNT_ENV,'POYNT_API_HOST_URL')
    POYNT_API_VERSION = POYNT_CONFIG.get(POYNT_ENV,'POYNT_API_VERSION')
    POYNT_AUTHZ_HOST_URL = POYNT_CONFIG.get(POYNT_ENV,'POYNT_AUTHZ_HOST_URL')
    BUSINESS_ID = POYNT_CONFIG.get(POYNT_ENV,'BUSINESS_ID')
    STORE_ID = POYNT_CONFIG.get(POYNT_ENV,'STORE_ID')
    APPLICATION_ID = POYNT_CONFIG.get(POYNT_ENV,'APPLICATION_ID')
    PRIVATE_KEY_FILE = POYNT_CONFIG.get(POYNT_ENV,'PRIVATE_KEY_FILE')
    PUBLIC_KEY_FILE = POYNT_CONFIG.get(POYNT_ENV,'PUBLIC_KEY_FILE')

    if(has_crypto):
        poyntAPI = PoyntAPI(POYNT_API_HOST_URL, APPLICATION_ID)
        if DEBUG == True:
            poyntAPI.debug = DEBUG
        if poyntAPI.getAccessToken() == True:
            poyntAPI.getCatalogs(BUSINESS_ID)
            poyntAPI.uploadProductCatalog(BUSINESS_ID)
            poyntAPI.getCatalogs(BUSINESS_ID)
            poyntAPI.getProducts(BUSINESS_ID)
            poyntAPI.getTaxes(BUSINESS_ID)
            poyntAPI.getCustomers(BUSINESS_ID)
            poyntAPI.getHooks(BUSINESS_ID)
            poyntAPI.getBusiness(BUSINESS_ID)
            poyntAPI.getBusinessUsers(BUSINESS_ID)
            poyntAPI.createOrder(BUSINESS_ID, STORE_ID)
            poyntAPI.getOrders(BUSINESS_ID)
            poyntAPI.refreshAccessToken()
        else:
            print "Cannot continue without an AccessToken!"
    else:
        print '\'cryptography\' package is required!'

if __name__ == "__main__":
    main(sys.argv[1:])
