# ============== IMPORTS ==============

import ConfigParser
import json
import logging
import sqlite3
from logging.handlers import RotatingFileHandler
from math import ceil
from urllib import urlencode
from os import listdir
from os.path import basename
from uuid import uuid4 as randomID
from time import time as timestamp
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify, g

# ============== GLOBAL VARS ==============

app = Flask(__name__)
app.secret_key="41wZ9nAkS!hKrk5t#0GI"
socketio = SocketIO(app)
# app_config: Will be loaded in 'init()'
app_config = { 'logging': {}, 'about': {}, 'repo': {}, 'db': {} }
app_nav = [
	{'name': "Home", 'path': "/"},
	{'name': "About", 'path': "/about"},
	{'name': "App", 'path': "/app"}
]
app_keys = {'private':"", 'public':""}
connected_users = {}
chat_discussions = {}
api_tokens = {}
# ThatiSREALLYaGooDSecret

class NotFoundEx(Exception):
	msg = "Ressource not found."

	def __init__(self, msg=None):
		Exception.__init__(self)
		if msg is not None:
			self.msg=msg

	def __str__(self):
		return self.msg

# ============== ROUTES ==============

@app.route('/')
def route_root():
	logRequest()
	flash("Welcome !")
	data = {'config': app_config, 'nav': {'pages': app_nav, 'active': "/"}}
	return render_template('index.html', data=data)

@app.route('/about')
def route_about():
	logRequest()
	data = {'config': app_config, 'nav': {'pages': app_nav, 'active': "/about"}}
	return render_template('about.html', data=data)

@app.route('/app')
def route_application():
	logRequest()
	data = {'config': app_config, 'nav': {'pages': app_nav, 'active': "/app"}}
	return render_template('app.html', data=data)

# -------------- API -------------- #

@app.route('/api', methods=['GET'])
def route_apiRoot():
	logRequest()
	data = {'status': 'OK'}
	return jsonify(data)
@app.route('/api', methods=['OPTIONS'])
def routeI_apiRoot():
	logRequest()
	data = {'endpoint': '/api', 'routes': [{'route': '/', 'desc': "Returns informations on the status of the service."}] }
	return jsonify(data)

@app.route('/api/login', methods=['POST'])
def route_apiLogin():
	logRequest()
	data = request.get_json()
	if data is None:
		app.logger.error('API_LOGIN | No JSON in request !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'No JSON content found.'}), 400
	if data.get('email', None) is None:
		app.logger.error('API_LOGIN | No email in request !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'No email found.'}), 400
	if data.get('password', None) is None:
		app.logger.error('API_LOGIN | No password in request !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'No password found.'}), 400
	cursor = get_db().cursor()
	print str(data['email'])
	row = cursor.execute("SELECT * FROM users WHERE email = ?", (str(data['email']),) ).fetchone();
	if row is None:
		app.logger.error('API_LOGIN | Email not found, email: '+data['email'])
		return jsonify({'status': 'error', 'error': 'LOGIN_ERROR', 'message': 'Invalid email or password !'}), 401
	if row['hashedPW'] != data['password']:
		app.logger.error('API_LOGIN | Invalid password, expected: '+row['hashedPW']+', found: '+data['password'])
		return jsonify({'status': 'error', 'error': 'LOGIN_ERROR', 'message': 'Invalid email or password !'}), 401
	con = get_db()
	cur = con.cursor()
	cur.execute("UPDATE users SET lastOnline = ? WHERE id = ?", (timestamp(),row['id']) )
	con.commit()
	data = {'status': 'OK', 'userID': row['id'], 'pseudo': row['pseudo'], 'token': gen_token(row['id'])}
	return jsonify(data)

@app.route('/api/users', methods=['GET'])
def route_apiUsers():
	logRequest()
	cursor = get_db().cursor()
	row = cursor.execute("SELECT COUNT(*) as count FROM users").fetchone();
	if row is None:
		app.logger.error('USERS | Returned NONE !')
		return jsonify({'status': 'error', 'error': 'DB_ERROR', 'message': 'Error when performing DB request. Returned None'}), 500
	data = {'status': 'OK', 'count': row['count']}
	return jsonify(data)

@app.route('/api/users/<int:userID>', methods=['GET'])
def route_apiUser_id(userID):
	logRequest()
	cursor = get_db().cursor()
	row = cursor.execute("SELECT * FROM users WHERE id = ?", (userID,) ).fetchone();
	if row is None:
		app.logger.error('USER_INFO | UserID not found ! id: '+str(userID))
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	data = {'status': 'OK', 'id': row['id'], 'pseudo': row['pseudo']}
	return jsonify(data)

@app.route('/api/users/<pseudo>', methods=['GET'])
def route_apiUser_pseudo(pseudo):
	logRequest()
	cursor = get_db().cursor()
	row = cursor.execute("SELECT * FROM users WHERE pseudo = ?", (pseudo,) ).fetchone();
	if row is None:
		app.logger.error('USER_INFO | Pseudo not found ! pseudo: '+pseudo)
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	data = {'status': 'OK', 'id': row['id'], 'pseudo': row['pseudo'], 'isOnline': False, 'lastOnline': row['lastOnline']}
	if connected_users.get(str(row['id']), None) is not None:
		del data['lastOnline']
		data['isOnline'] = True
	return jsonify(data)

@app.route('/api/users/<int:userID>/contacts', methods=['GET'])
def route_apiUserContacts_id(userID):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_CONTACTS | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_CONTACTS | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromID(userID)
	if user is None:
		app.logger.error('USER_CONTACTS | User not found ! id: '+userID)
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	if not token_canAccess_profileDetails(req_token, userID):
		app.logger.error('USER_CONTACTS | Access forbidden ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'ACCESS_ERROR', 'message': 'This token is not granted access to this ressource.'}), 403
	rows = db_getContacts_fromUserID(userID)
	data = {'status': 'OK', 'contacts': []}
	for row in rows:
		uInfo = {'id': row['id'], 'pseudo': row['pseudo'], 'tags': row['tags'], 'isOnline': False, 'lastOnline': row['lastOnline']}
		if user_isOnline(row['id']):
			del uInfo['lastOnline']
			uInfo['isOnline'] = True
		data['contacts'].append(uInfo)
	return jsonify(data)

@app.route('/api/users/<pseudo>/contacts', methods=['GET'])
def route_apiUserContacts_pseudo(pseudo):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_CONTACTS | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_CONTACTS | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromPseudo(pseudo)
	if user is None:
		app.logger.error('USER_CONTACTS | Pseudo not found ! pseudo: '+pseudo)
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	if not token_canAccess_profileDetails(req_token, user['id']):
		app.logger.error('USER_CONTACTS | Access forbidden ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'ACCESS_ERROR', 'message': 'This token is not granted access to this ressource.'}), 403
	rows = db_getContacts_fromPseudo(pseudo)
	data = {'status': 'OK', 'contacts': []}
	for row in rows:
		uInfo = {'id': row['id'], 'pseudo': row['pseudo'], 'tags': row['tags'], 'isOnline': False, 'lastOnline': row['lastOnline']}
		if user_isOnline(row['id']):
			del uInfo['lastOnline']
			uInfo['isOnline'] = True
		data['contacts'].append(uInfo)
	return jsonify(data)

@app.route('/api/users/<int:userID>/public-key', methods=['GET'])
def route_apiUserPubkey_id(userID):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_PUBKEY | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_PUBKEY | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromID(userID)
	if user is None:
		app.logger.error('USER_PUBKEY | User not found ! id: '+userID)
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	cursor = get_db().cursor()
	row = cursor.execute("SELECT key FROM publicKeys WHERE userID = ?", (userID,) ).fetchone();
	if row is None:
		app.logger.error('USER_PUBKEY | Returned NONE !')
		return jsonify({'status': 'error', 'error': 'SYSTEM_ERROR', 'message': 'Error. No public key could be found for this user.'}), 500
	data = {'status': 'OK', 'public_key': row['key']}
	return jsonify(data)

@app.route('/api/users/<pseudo>/public-key', methods=['GET'])
def route_apiUserPubkey_pseudo(pseudo):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_PUBKEY | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_PUBKEY | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromPseudo(pseudo)
	if user is None:
		app.logger.error('USER_PUBKEY | User not found ! id: '+user['id'])
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	cursor = get_db().cursor()
	row = cursor.execute("SELECT key FROM publicKeys WHERE userID = ?", (user['id'],) ).fetchone();
	if row is None:
		app.logger.error('USER_PUBKEY | Returned NONE !')
		return jsonify({'status': 'error', 'error': 'SYSTEM_ERROR', 'message': 'Error. No public key could be found for this user.'}), 500
	data = {'status': 'OK', 'public_key': row['key']}
	return jsonify(data)

@app.route('/api/users/<int:userID>/private-key', methods=['GET'])
def route_apiUserPrivkey_id(userID):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_PRIVKEY | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_PRIVKEY | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromID(userID)
	if user is None:
		app.logger.error('USER_PRIVKEY | User not found ! id: '+userID)
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	if not token_canAccess_privateKey(req_token, userID):
		app.logger.error('USER_PRIVKEY | Access forbidden ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'ACCESS_ERROR', 'message': 'This token is not granted access to this ressource.'}), 403
	cursor = get_db().cursor()
	row = cursor.execute("SELECT encKey FROM privateKeys WHERE userID = ?", (userID,) ).fetchone();
	if row is None:
		app.logger.error('USER_PRIVKEY | Returned NONE !')
		return jsonify({'status': 'error', 'error': 'SYSTEM_ERROR', 'message': 'Error. No private key could be found for this user.'}), 500
	data = {'status': 'OK', 'public_key': row['encKey']}
	return jsonify(data)

@app.route('/api/users/<pseudo>/private-key', methods=['GET'])
def route_apiUserPrivkey_pseudo(pseudo):
	logRequest()
	req_token = request.args.get('token', None)
	if req_token is None:
		app.logger.error('USER_PRIVKEY | Missing token !')
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	if not token_isValid(req_token):
		app.logger.error('USER_PRIVKEY | Invalid token ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'REQUEST_ERROR', 'message': 'Missing or invalid token'}), 400
	user = db_getUser_fromPseudo(pseudo)
	if user is None:
		app.logger.error('USER_PRIVKEY | User not found ! id: '+user['id'])
		return jsonify({'status': 'error', 'error': 'NOT_FOUND_ERROR', 'message': 'No such user.'}), 404
	if not token_canAccess_privateKey(req_token, user['id']):
		app.logger.error('USER_PRIVKEY | Access forbidden ! token: '+req_token)
		return jsonify({'status': 'error', 'error': 'ACCESS_ERROR', 'message': 'This token is not granted access to this ressource.'}), 403
	cursor = get_db().cursor()
	row = cursor.execute("SELECT encKey FROM privateKeys WHERE userID = ?", (user['id'],) ).fetchone();
	if row is None:
		app.logger.error('USER_PRIVKEY | Returned NONE !')
		return jsonify({'status': 'error', 'error': 'SYSTEM_ERROR', 'message': 'Error. No private key could be found for this user.'}), 500
	data = {'status': 'OK', 'public_key': row['encKey']}
	return jsonify(data)

# -------------- SOCKET -------------- #

@socketio.on('connect')
def socket_connect():
	app.logger.info('SOCKET | New user! ')

@socketio.on('init')
def socket_init(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		app.logger.info('SOCKET | INIT: '+data.get('pseudo','UNKNOWN')+'['+str(data.get('userID', -1))+'] token: '+data.get('token', 'NO_TOKEN'))
		uInfo = api_tokens[data['token']]
		connected_users[str(uInfo['user'])] = timestamp()
		join_room(str(uInfo['user'])+"-info")

@socketio.on('ask')
def socket_askDisc(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		contacts = db_getContacts_fromUserID(uInfo['user'])
		if data.get('user', -1) not in contacts or not user_isOnline(data['user']):
			return
		if discussion_find(uInfo['user'], data['user']) is not None:
			return
		app.logger.info('SOCKET | Requesting discussion : '+uInfo['user']+' > '+data['user'])
		discID = randomID().hex
		while chat_discussions.get(discID, None) is not None:
			discID = randomID().hex
		disc = {'id': discID,'userA': uInfo['user'], 'userB': data['user'], 'accepted': False}
		chat_discussions[discID] = disc
		emit("ask", {'discussion': disc, 'message': 'I want to talk.'}, namespace='/user-'+str(disc['userB']))

@socketio.on('accept')
def socket_acceptDisc(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		if data.get('discussion', None) is None or chat_discussions.get(data['discussion'], None) is None:
			return
		disc = chat_discussions[data['discussion']]
		if disc['userA']!=uInfo['user'] and disc['userB']!=uInfo['user']:
			return
		if not user_isOnline(disc['userA']) or not user_isOnline(disc['userB']):
			return
		app.logger.info('SOCKET | Discussion started. '+disc['id'])
		chat_discussions[disc['id']]['accepted'] = True
		emit("accept", {'discussion': disc}, namespace='/user-'+str(disc['userA']))

@socketio.on('reject')
def socket_rejectDisc(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		if data.get('discussion', None) is None or chat_discussions.get(data['discussion'], None) is None:
			return
		disc = chat_discussions[data['discussion']]
		if disc['userA']!=uInfo['user'] and disc['userB']!=uInfo['user']:
			return
		if not user_isOnline(disc['userA']) or not user_isOnline(disc['userB']):
			return
		app.logger.info('SOCKET | Discussion refused. '+disc['id'])
		emit("reject", {'discussion': disc}, namespace='/user-'+str(disc['userA']))
		del chat_discussions[disc['id']]

@socketio.on('leave')
def socket_leaveDisc(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		if data.get('discussion', None) is None or chat_discussions.get(data['discussion'], None) is None:
			return
		disc = chat_discussions[data['discussion']]
		if disc['userA']!=uInfo['user'] and disc['userB']!=uInfo['user']:
			return
		if not user_isOnline(disc['userA']) or not user_isOnline(disc['userB']):
			return
		app.logger.info('SOCKET | Leave discussion. ')
		del chat_discussions[disc['id']]

@socketio.on('message')
def socket_message(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		if data.get('discussion', None) is None or chat_discussions.get(data['discussion'], None) is None:
			return
		disc = chat_discussions[data['discussion']]
		if disc['userA']!=uInfo['user'] and disc['userB']!=uInfo['user']:
			return
		if not user_isOnline(disc['userA']) or not user_isOnline(disc['userB']):
			return
		app.logger.info('SOCKET | Message.')
		msg = {'sender': uInfo['user'], 'discussion': disc['id'], 'message': data['message']}
		emit("message",msg, namespace='/user-'+disc['userA'])
		emit("message",msg, namespace='/user-'+disc['userB'])

@socketio.on('join')
def socket_join(data):
	if token_isValid(data.get('token', 'NO_TOKEN')):
		uInfo = api_tokens[data['token']]
		if data.get('discussion', None) is None or chat_discussions.get(data['discussion'], None) is None:
			return
		disc = chat_discussions[data['discussion']]
		if disc['userA']!=uInfo['user'] and disc['userB']!=uInfo['user']:
			return
		if not user_isOnline(disc['userA']) or not user_isOnline(disc['userB']):
			return
		app.logger.info('SOCKET | Join.')
		msg = {'sender': uInfo['user'], 'discussion': disc['id'], 'message': "has joined the discussion."}
		emit("join",msg, namespace='/user-'+disc['userA'])
		emit("join",msg, namespace='/user-'+disc['userB'])

# ============== ERRORS ============== #

@app.errorhandler(404)
@app.errorhandler(NotFoundEx)
def error_notFound(error):
	data = {'config': app_config, 'nav': {'pages': app_nav, 'active': "/error"}}
	app.logger.error("ERROR - "+str(error))
	return render_template('e404.html', data=data), 404

@app.errorhandler(500)
def error_notFound(error):
	app.logger.error("ERROR - "+str(error))

# ============== FUNCTIONS ============== #

def splitListIntoPages(data, urlArgs):
	args = urlArgs.to_dict()
	dList = data['list']
	PAGE_LENGTH = app_config['graphic']['items_per_page']
	NB_PAGES = int( ceil( len(dList)/float(PAGE_LENGTH) ) )
	page = int(args.pop('page')) if 'page' in args else 1
	iMin = (page-1)*PAGE_LENGTH
	iMax = (page)*PAGE_LENGTH
	data['list'] = dList[iMin:iMax]
	data['pages'] = {'cur': page, 'list': []}
	if page > 1:
		data['pages']['prev'] = (page-1)
	if page < NB_PAGES:
		data['pages']['next'] = (page+1)
	data['pages']['list'] = range(max(1, page-3), min(NB_PAGES, page+3)+1)
	url_prefix = urlencode(args)
	data['pages']['prefix'] = "?"+url_prefix+( "" if url_prefix == "" else "&" )+"page="
	return data

def user_isOnline(uID):
	return connected_users.get(str(uID), None) is not None

def discussion_find(userA, userB):
	for disc in chat_discussions:
		if disc['userA']==userA and disc['userB']==userB:
			return disc
		if disc['userA']==userB and disc['userB']==userA:
			return disc
	return None

def gen_token(userID):
	for index in api_tokens:
		if api_tokens[index]['user'] == userID:
			return index
	token = randomID().hex
	while api_tokens.get(token, None) is not None:
		token = randomID().hex
	api_tokens[token] = {'user': userID, 'time': timestamp()}
	return token

def token_isValid(token):
	found = api_tokens.get(token, None)
	if found is None: # Token doesn't exist
		return False
	if timestamp()-found['time'] > 3600: # Token expired (>1h)
		del api_tokens[token]
		return False
	return True

def token_canAccess_profileDetails(token, uID):
	found = api_tokens.get(token, None)
	if found['user']==0: # Admin
		return True
	if found['user']==uID: # Same user
		return True
	return False

def token_canAccess_privateKey(token, uID):
	found = api_tokens.get(token, None)
	if found['user']==0: # Admin ok, TODO: Remove admin access
		return True
	if found['user']==uID: # Same user
		return True
	return False

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
	db = getattr(g, 'db', None)
	if db is None:
		db = sqlite3.connect(app_config['db']['database'])
		db.row_factory = dict_factory
		g.db = db
	return db

def db_getUser_fromPseudo(pseudo):
	cursor = get_db().cursor()
	row = cursor.execute("SELECT * FROM users WHERE pseudo = ?", (pseudo,) ).fetchone();
	return row

def db_getUser_fromID(userID):
	cursor = get_db().cursor()
	row = cursor.execute("SELECT * FROM users WHERE id = ?", (userID,) ).fetchone();
	return row

def db_getContacts_fromUserID(userID):
	cursor = get_db().cursor()
	rows = cursor.execute("""
		SELECT U.*, C.tags FROM contacts C, users U WHERE C.userID = ? AND C.contact = U.id
	""", (userID,) ).fetchall();
	return rows

def db_getContacts_fromPseudo(pseudo):
	cursor = get_db().cursor()
	rows = cursor.execute("""
		SELECT U.*, C.tags FROM contacts C, users U WHERE C.userID = (SELECT id FROM users WHERE pseudo = ?)
		AND C.contact = U.id
	""", (pseudo,) ).fetchall();
	return rows

def logRequest():
	app.logger.info(request.method+": "+request.url)

# ============== SETUP ============== #

@app.teardown_appcontext
def close_db(ex):
	db = getattr(g, 'db', None)
	if db is not None:
		db.close()

def init(app):
	app.logger.info("INIT - Initializing application ...")
	config = ConfigParser.ConfigParser ()
	try:
		config_location = "etc/defaults.cfg"
		config.read(config_location)
		# App
		app_config['about']['name'] = config.get("app", "name")
		app_config['about']['author'] = config.get("app", "author")
		app_config['about']['contact'] = config.get("app", "contact")
		# Main config
		app.config['DEBUG'] = config.get("config", "debug")
		app.config['ip_address'] = config.get("config", "ip_address")
		app.config['port'] = config.get("config", "port")
		app.config['url'] = config.get("config", "url")
		# Database
		app_config['db']['database'] = config.get("db", "database")
		app_config['db']['drop'] = config.get("db", "drop")
		app_config['db']['create'] = config.get("db", "create")
		# Logging
		app_config['logging']['file'] = config.get("logging", "name")
		app_config['logging']['location'] = config.get("logging", "location")
		app_config['logging']['level'] = config.get("logging", "level")
		# Logging
		app_config['repo']['git'] = config.get("repo", "git")
		app_config['repo']['url'] = config.get("repo", "url")
		app_config['repo']['user'] = config.get("repo", "user")
		app_config['repo']['name'] = config.get("repo", "name")
	except IOError as e:
		app.logger.error("ERROR - Could not read configs from: "+config_location)
		app.logger.error("\t>>"+str(e))
	try:
		pubkeyFile = open('keys/pubkey.txt','r')
		app_keys['public'] = pubkeyFile.read()
		pubkeyFile.close()
		privkeyFile = open('keys/privkey.txt','r')
		app_keys['private'] = privkeyFile.read()
		privkeyFile.close()
	except IOError as e:
		app.logger.error("ERROR - Could not get application keys.")
		app.logger.error("\t>>"+str(e))

def logs(app):
	log_pathname = app_config['logging']['location'] + app_config['logging']['file']
	file_handler = RotatingFileHandler(log_pathname, maxBytes=1024*1024*10, backupCount=1024)
	file_handler.setLevel(app_config['logging']['level'])
	formatter = logging.Formatter("%(levelname)s | %(asctime)s | %(module)s | %(funcName)s | %(message)s")
	file_handler.setFormatter(formatter)
	app.logger.setLevel(app_config['logging']['level'])
	app.logger.addHandler(file_handler)

if __name__ == '__main__':
	init(app)
	logs(app)
	app.logger.info("START - Application started !")
	socketio.run(
		app,
	    host=app.config['ip_address'],
	    port=int(app.config['port'])
	)
	app.logger.info("STOP - Application ended !")
