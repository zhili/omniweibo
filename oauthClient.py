import oauth as oauth
from urllib2 import Request
import httplib
from urllib import quote as urlquote,unquote as urlunquote
from google.appengine.ext import db
from cgi import parse_qs,parse_qsl
from hmac import new as hmac
from hashlib import sha1, sha256, sha512
from Crypto.Cipher import AES
import base64

# settings for the local test consumer
SERVER = 'api.t.sina.com.cn'
PORT = 80

# fake urls for the test server (matches ones in server.py)
REQUEST_TOKEN_URL = 'http://api.t.sina.com.cn/oauth/request_token'
ACCESS_TOKEN_URL = 'http://api.t.sina.com.cn/oauth/access_token'
AUTHORIZATION_URL = 'http://api.t.sina.com.cn/oauth/authorize'
CALLBACK_URL = 'http://api.t.sina.com.cn/oauth/request_token_ready'
RESOURCE_URL = 'http://photos.example.net/photos'
STATUSUPDATE_URL = 'http://api.t.sina.com.cn/statuses/update.json'

# key and secret granted by the service provider for this consumer application - same as the MockOAuthDataStore
CONSUMER_KEY = '3538199806'
CONSUMER_SECRET = '18cf587d60e11e3c160114fd92dd1f2b'

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

class TempTokenModel(db.Model):

    token    = db.StringProperty(required=True)
    secret   = db.StringProperty(required=True)
    created  = db.DateTimeProperty(auto_now_add=True)

class AuthTokenModel(db.Model):

    username = db.StringProperty(required=True)
    token    = db.StringProperty(required=True)
    secret   = db.StringProperty(required=True)
    created  = db.DateTimeProperty(auto_now_add=True)

    def create_aes(self, self_key):
        if isinstance(self_key, unicode):
            self_key = self_key.encode('ascii')
        if isinstance(self.username, unicode):
            self.username = self.username.encode('ascii')
        data = hmac(
            self.username, self_key, sha512
            ).digest()
        return AES.new(data[:32], AES.MODE_CBC,data[32:32])
 
    def encrypt(self, self_key):
        self.token  = EncodeAES(self.create_aes(self_key) , self.token)
        self.secret = EncodeAES(self.create_aes(self_key),  self.secret)
    
    def decrypt(self, self_key):
        # logging.debug('xx_token:%s' % self.token)
        self.token  = DecodeAES(self.create_aes(self_key), self.token)
        # logging.debug('yy_token:%s' % self.token)
        self.secret = DecodeAES(self.create_aes(self_key), self.secret)

class TOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url='', authorization_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.authorization_url = authorization_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))

    def fetch_request_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.request_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())

    def fetch_access_token(self, oauth_request):
        # via headers
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.access_token_url, headers=oauth_request.to_header()) 
        response = self.connection.getresponse()
        result = self.extract_credentials(response.read())
        return result['token'], result['secret'], result['user_id']
    
    # from gtap
    def extract_credentials(self, result):
        token = None
        secret = None
        screen_name = None
        parsed_results = parse_qs(result, keep_blank_values=False )

        if "oauth_token" in parsed_results:
            token = parsed_results["oauth_token"][0]

        if "oauth_token_secret" in parsed_results:
            secret = parsed_results["oauth_token_secret"][0]

        if "user_id" in parsed_results:
            user_id = parsed_results["user_id"][0]

        return {
            "token": token,
            "secret": secret,
            "user_id": user_id
        }
        
        
    def authorize_token(self, oauth_request):
        # via url
        # -> typically )ust some okay response
        self.connection.request(oauth_request.http_method, oauth_request.to_url()) 
        response = self.connection.getresponse()
        return response.read()

class TSinaOauthClient():

   def __init__(self, ):
      self.client = TOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL, ACCESS_TOKEN_URL, AUTHORIZATION_URL)
      self.consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
      self.signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
      self.signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()

   def get_authorization_url(self, call_back=None):
      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, http_url=self.client.request_token_url)
      oauth_request.sign_request(self.signature_method_plaintext, self.consumer, None)
      request_token = self.client.fetch_request_token(oauth_request)
      self.saveTempToken(request_token)
      oauth_request = oauth.OAuthRequest.from_token_and_callback(token=request_token, callback=call_back, http_url=self.client.authorization_url)

      return oauth_request.to_url()

   def get_access_token(self, token_, verifier_):
      tokenSecret = self.restoreTokenFromKey(token_)
      request_token = oauth.OAuthToken(token_, tokenSecret)
      oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=request_token, verifier=verifier_, http_url=self.client.access_token_url)
      oauth_request.sign_request(self.signature_method_plaintext, self.consumer, request_token)
      return self.client.fetch_access_token(oauth_request)

   def saveTempToken(self, token):
      res = TempTokenModel.all().filter('token =', token.key)
      if res.count() > 0:
         db.delete(res)

      token_key = '###' + token.key
      secret = '###' + token.secret

      theToken = TempTokenModel(token=token_key, secret=secret)
      theToken.put()
   
   def restoreTokenFromKey(self, tokenKey):
      queryKey = '###' + tokenKey

      result = TempTokenModel.gql("""Where token = :1 LIMIT 1""",
            queryKey).get()
      if not result:
         return None
      else:
         return result.secret[3:]

   def get_access_from_db(self, username, password):
      result = AuthTokenModel.gql("""
            WHERE
                username = :1
            LIMIT
                1
        """, username.lower()).get()
      
      if not result:
         access_token = None
         access_secret = None
      else:
         result.decrypt(password)
         if result.token[:3]=='###' and result.secret[:3]=='###':
             access_token = result.token[3:]
             access_secret = result.secret[3:]
         else:
             access_token = None
             access_secret = None
      return access_token, access_secret

   def save_user_info_into_db(self, username, password, token, secret):
      res = AuthTokenModel.all().filter('username =', username)
      if res.count() > 0:
         db.delete(res)
      token  = '###' + token
      secret = '###' + secret
      
      auth = AuthTokenModel(
                     username=username.lower(),
                     secret=secret,
                     token=token)
      auth.encrypt(password)
      auth.put()

class WeiboClient():
    """the simple Tsina client.
    """
    
    def __init__(self, accessToken, accessSecret):
        """class init method
        
        Arguments:
        - `accessToken`:
        - `accessSecret`:
        """
        self._accessToken = oauth.OAuthToken(accessToken, accessSecret)
        self._connection = httplib.HTTPConnection("%s:%d" % (SERVER, PORT))
        self.signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()
        self.consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)

    def updateStatus(self, state):
        """make a tweet
        
        Arguments:
        - `state`:the tweets to send
        """
        parameters = {'status': state,}
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer, token=self._accessToken, http_method='POST', http_url=STATUSUPDATE_URL, parameters=parameters)
        oauth_request.sign_request(self.signature_method_hmac_sha1, self.consumer, self._accessToken)
        headers = {'Content-Type' :'application/x-www-form-urlencoded'}
        self._connection.request('POST', STATUSUPDATE_URL, body=oauth_request.to_postdata(), headers=headers)
        response = self._connection.getresponse()
        #print response.read()


