from google.appengine.ext import db
import random

class Quotes(db.Model):
    text = db.StringProperty()
    rand = db.FloatProperty()
    def __str__(self):
        return self.text
