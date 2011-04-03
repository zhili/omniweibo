# -*- coding: utf-8 -*-
# Copyright under  the latest Apache License 2.0

import wsgiref.handlers, urlparse, base64, logging
from cgi import parse_qsl
from google.appengine.ext import webapp
from google.appengine.api import urlfetch, urlfetch_errors
from wsgiref.util import is_hop_by_hop
from uuid import uuid4
import oauthClient
from models import Quotes
import random
from google.appengine.ext import db

omniweibo_message = """
    <html>
        <head>
        <title>OMNIWEIBO</title>
        <link href='https://appengine.google.com/favicon.ico' rel='shortcut icon' type='image/x-icon' />
        <style>body { padding: 20px 40px; font-family: Verdana, Helvetica, Sans-Serif; font-size: medium; }</style>
        </head>
        <body><h2>OMNIWEIBO is running!</h2></p>
        <p><a href='/oauth/session'><img src='/static/sign-in-with-twitter.png' border='0'></a> 
        or <a href='/oauth/change'>change your key here</a></p>
         <p><a href='/updatestatus'>update state here</a></p>
         <p><a href='/delete'>delete state here</a></p>
    </body></html>
    """

def success_output(handler, content, content_type='text/html'):
    # handler.response.status = '200 OK'
    handler.response.headers.add_header('Content-Type', content_type)
    handler.response.out.write(content)

def error_output(handler, content, content_type='text/html', status=503):
    handler.response.set_status(503)
    handler.response.headers.add_header('Content-Type', content_type)
    handler.response.out.write("Gtap Server Error:<br />")
    return handler.response.out.write(content)

def shuffle_random_quote():
    """
    """
    result = Quotes.gql("""
            WHERE
                rand > :1
            ORDER BY rand LIMIT 
                1
        """, random.random()).get()
    return result.text

class MainPage(webapp.RequestHandler):

    def get(self, mode=""):
        if mode=="":
            global omniweibo_message
            return success_output(self, omniweibo_message )
        
        if mode=="updatestatus":
            user_access_token = None
            callback_url = "%s/oauth/verify" % self.request.host_url
            oClient = oauthClient.TSinaOauthClient()
            user_access_token, user_access_secret  = oClient.get_access_from_db('1774607874', '7227ec8d-cca9-4eef-88c9-4963ade332ee')
            if user_access_token is None :
                return error_output(self, 'Can not find this user from db')
            weiboClient = oauthClient.WeiboClient(user_access_token, user_access_secret)
            tweets = shuffle_random_quote().encode('utf8') + "#3G就选沃#"
            weiboClient.updateStatus(tweets)
            # 
        if mode=='delete':
            res = Quotes.all()
            db.delete(res)
            


class OauthPage(webapp.RequestHandler):

    def get(self, mode=""):
        callback_url = "%s/oauth/verify" % self.request.host_url
        client = oauthClient.TSinaOauthClient()
        request_token = None

        if mode=='session':
            # step C Consumer Direct User to Service Provider
            try:
                url = client.get_authorization_url(call_back=callback_url)
                self.redirect(url)
            except Exception,error_message:
                self.response.out.write( error_message )


        if mode=='verify':
            # step D Service Provider Directs User to Consumer
            auth_token = self.request.get("oauth_token")
            auth_verifier = self.request.get("oauth_verifier")

            # step E Consumer Request Access Token 
            # step F Service Provider Grants Access Token
            try:
                access_token, access_secret, user_id = client.get_access_token(auth_token, auth_verifier)
                self_key = '%s' % uuid4()
                # Save the auth token and secret in our database.
                client.save_user_info_into_db(username=user_id, password=self_key, 
                                              token=access_token, secret=access_secret)
                show_key_url = '%s/oauth/showkey?name=%s&key=%s' % (
                                                                       self.request.host_url, 
                                                                       user_id, self_key)
                self.redirect(show_key_url)
            except Exception,error_message:
                logging.debug("oauth_token:" + auth_token)
                logging.debug("oauth_verifier:" + auth_verifier)
                logging.debug( error_message )
                self.response.out.write( error_message )
        
        if mode=='showkey':
            screen_name = self.request.get("name")
            self_key = self.request.get("key")
            out_message = """
                <html><head><title>OMNIWEIBO</title>
                <style>body { padding: 20px 40px; font-family: Courier New; font-size: medium; }</style>
                </head><body><p>
                your twitter's screen name : <b>#screen_name#</b> <br /><br />
                the Key of this API : <b>#self_key#</b> <a href="#api_host#/oauth/change?name=#screen_name#&key=#self_key#">you can change it now</a><br /><br />
                </p>></body></html>
                """
            out_message = out_message.replace('#api_host#', self.request.host_url)
            out_message = out_message.replace('#screen_name#', screen_name)
            out_message = out_message.replace('#self_key#', self_key)
            self.response.out.write( out_message )
        
        if mode=='change':
            screen_name = self.request.get("name")
            self_key = self.request.get("key")
            out_message = """
                <html><head><title>OMNIWEIBO</title>
                <style>body { padding: 20px 40px; font-family: Courier New; font-size: medium; }</style>
                </head><body><p><form method="post" action="%s/oauth/changekey">
                your screen name of Twitter : <input type="text" name="name" size="20" value="%s"> <br /><br />
                your old key of this API : <input type="text" name="old_key" size="50" value="%s"> <br /><br />
                define your new key of this API : <input type="text" name="new_key" size="50" value=""> <br /><br />
                <input type="submit" name="_submit" value="Change the Key">
                </form></p></body></html>
                """ % (self.request.host_url, screen_name, self_key)
            self.response.out.write( out_message )
        
            
    def post(self, mode=''):
        
        callback_url = "%s/oauth/verify" % self.request.host_url
        # client = oauth.TwitterClient(CONSUMER_KEY, CONSUMER_SECRET, callback_url)
        client = oauthClient.TSinaOauthClient()
        if mode=='changekey':
            screen_name = self.request.get("name")
            old_key = self.request.get("old_key")
            new_key = self.request.get("new_key")
            user_access_token, user_access_secret  = client.get_access_from_db(screen_name, old_key)
            
            if user_access_token is None or user_access_secret is None:
                logging.debug("screen_name:" + screen_name)
                logging.debug("old_key:" + old_key)
                logging.debug("new_key:" + new_key)
                self.response.out.write( 'Can not find user from db, or invalid old_key.' )
            else:
                try:
                    client.save_user_info_into_db(username=screen_name, password=new_key, 
                                                  token=user_access_token, secret=user_access_secret)
                    show_key_url = '%s/oauth/showkey?name=%s&key=%s' % (
                                                                        self.request.host_url, 
                                                                        screen_name, new_key)
                    self.redirect(show_key_url)
                except Exception,error_message:
                    logging.debug("screen_name:" + screen_name)
                    logging.debug("old_key:" + old_key)
                    logging.debug("new_key:" + new_key)
                    logging.debug( error_message )
                    self.response.out.write( error_message )

        if mode=='access_token':
            # TwitBird needs this to
            error_output(self, 'Oops!')


def main():
    application = webapp.WSGIApplication( [
        (r'/oauth/(.*)', OauthPage),
        (r'/(.*)',         MainPage)
        ], debug=True)
    wsgiref.handlers.CGIHandler().run(application)
    
if __name__ == "__main__":
  main()
