# --- --- IMPORTS --- ---

import ConfigParser
import json
import markdown
import logging
from logging.handlers import RotatingFileHandler
from math import ceil
from urllib import urlencode
from os import listdir
from os.path import basename
from flask import Flask, render_template, flash, redirect, url_for, request

# --- --- GLOBAL VARS --- ---

app = Flask(__name__)
app.secret_key="41wZ9nAkS!hKrk5t#0GI"
# app_config: Will be loaded in 'init()'
app_config = { 'logging': {}, 'about': {}, 'repo': {} }
app_nav = [
	{'name': "Home", 'path': "/"},
	{'name': "About", 'path': "/about"}
]

class NotFoundEx(Exception):
	msg = "Ressource not found."

	def __init__(self, msg=None):
		Exception.__init__(self)
		if msg is not None:
			self.msg=msg

	def __str__(self):
		return self.msg

# --- --- ROUTES --- ---

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

# --- --- ERRORS --- --- #

@app.errorhandler(404)
@app.errorhandler(NotFoundEx)
def error_notFound(error):
	data = {'config': app_config, 'nav': {'pages': app_nav, 'active': "/error"}}
	app.logger.error("ERROR - "+str(error))
	return render_template('e404.html', data=data), 404

@app.errorhandler(500)
def error_notFound(error):
	app.logger.error("ERROR - "+str(error))

# --- --- Processing funcions --- --- #

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

# --- --- SETUP --- ---

def logRequest():
	app.logger.info(request.method+": "+request.url)

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
	app.run(
	    host=app.config['ip_address'],
	    port=int(app.config['port'])
	)
	app.logger.info("STOP - Application ended !")
