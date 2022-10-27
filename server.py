import flask
from flask import render_template, request, Flask, g, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, Table, Column, Float, Integer, DateTime, String, MetaData, ForeignKey

import json
import random
import string
import os
import time
import datetime

from web3.auto import w3
from eth_account.messages import defunct_hash_message

from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies

from ethhelper import *

app = Flask(__name__,static_url_path='/static')
app.jinja_env.add_extension('jinja2.ext.do')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Setup the Flask-JWT-Extended extension
# log2(26^22) ~= 100 (pull at least 100 bits of entropy)
app.config['JWT_SECRET_KEY'] = ''.join(random.choice(string.ascii_lowercase) for i in range(22))
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = True
#app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
jwt = JWTManager(app)

@app.before_first_request
def setup():
  print("[+] running setup")
  try:
    db.create_all()
    print("[+] created users db")
  except:
    print("[+] users db already exists")

def generate_nonce(self, length=8):
  return ''.join([str(randint(0, 9)) for i in range(length)])

class Hits(db.Model):
  time = Column(DateTime,default=datetime.datetime.utcnow, primary_key=True)
  ipaddr = Column(String(80))
  headers = Column(String(800))

class User(db.Model):
  public_address = db.Column(db.String(80), primary_key=True, nullable=False, unique=True)
  nonce = db.Column(db.Integer(),nullable=False,default=generate_nonce,)

@app.route('/')
def landing():
  return render_template("index.html")

@app.route('/*.gif')
def clowntown():
  
  try:
    h = Hits()
    if request.headers['X-Forwarded-For']:
      h.ipaddr = request.headers['X-Forwarded-For']
    else:
      h.ipaddr = request.remote_addr

    h.headers = str(request.headers)
    db.session.add(h)
    db.session.commit()
  except Exception as e:
    print(str(e))

  return send_from_directory('static','clowntown.gif')

@app.route('/track')
def track():
  return render_template("track.html",hits=Hits.query.order_by(desc(Hits.time)).limit(100).all())

@app.route('/secret')
@jwt_required
def secret():
  current_user = get_jwt_identity()
  numtokens = tokencount(current_user)
  if numtokens > 100:
    msg="The Galaxy is on Orion's Belt"
  else:
    msg="You need more than 100 GST to view this message."
  return ("HELLO "+str(current_user)+" "+msg)

@app.route('/login', methods=['POST'])
def login():

    print("[+] creating session")

    print("info: "+(str(request.json)))

    public_address = request.json[0]
    signature = request.json[1]

    domain = "simple-flask-metamask.herokuapp.com"

    rightnow = int(time.time())
    sortanow = rightnow-rightnow%600
   
    original_message = 'Signing in to {} at {}'.format(domain,sortanow)
    print("[+] checking: "+original_message)
    message_hash = defunct_hash_message(text=original_message)
    signer = w3.eth.account.recoverHash(message_hash, signature=signature)
    print("[+] fascinating")

    if signer == public_address:
      print("[+] this is fine "+str(signer))
       # account.nonce = account.generate_nonce()
       # db.session.commit()
    else:
        abort(401, 'could not authenticate signature')

    print("[+] OMG looks good")

    access_token = create_access_token(identity=public_address)

    resp = jsonify({'login': True})
    set_access_cookies(resp, access_token)
    return resp, 200
