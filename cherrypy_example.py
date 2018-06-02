#!/usr/bin/python
""" cherrypy_example.py

	COMPSYS302 - Software Design
	Author: Andrew Chen (andrew.chen@auckland.ac.nz)
	Last Edited: 19/02/2018

	This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
# Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10005

import cherrypy
from hashlib import sha256
from urllib import urlencode
import urllib
import urllib2
import os.path
import json
import dbManager
import atexit
import calendar
import time
import logging
from mimetypes import MimeTypes
import hmac
import base64
import struct
import hashlib

current_dir = os.path.dirname(os.path.abspath(__file__))
#secret = 'MZXW633PN5XW6MZX'

class IgnoreURLFilter(logging.Filter):
	def __init__(self, ignore):
		self.ignore = 'GET /' + ignore

	def filter(self, record):
		return not self.ignore in record.getMessage()

class MainApp(object):
	# CherryPy Configuration
	_cp_config = {'tools.encode.on': True,
				  'tools.encode.encoding': 'utf-8',
				  'tools.sessions.on': 'True',
				  }

	# If they try somewhere we don't know, catch it here and send them to the right place.

	@cherrypy.expose
	def default(self, *args, **kwargs):
		"""The default page, given when we don't recognise where the request is for."""
		Page = "I don't know where you're trying to go, so have a 404 Error.</br>"
		Page += "<a href='/'> Return to home"
		cherrypy.response.status = 404 
		return Page

	# Home Page -------------------------------------------------------------------
	@cherrypy.expose
	def index(self):
		try:
			"""
			userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
			data = {'username': cherrypy.session.get('username'), 'password': cherrypy.session.get('password'), 'enc' : 0, 'json' : 1}
			post = urlencode(data)
			response = urllib2.urlopen(userListUrl, post)
			resp = response.read()
			# print resp
			jsonUserList = json.loads(resp)
			print resp

			dbManager.openDB("mydb")
			dbManager.addToUserTable("mydb", jsonUserList)
			dbManager.readUserTable("mydb")
			"""
			if cherrypy.session.get('username') is None:
				Page = open(os.path.join('static', 'index.html'))
				return Page

			url = urllib2.Request('http://cs302.pythonanywhere.com/listUsers')
			response = urllib2.urlopen(url).read()

			allUsersList = response.split(',')
			allUsersList = [', '.join(allUsersList[n:]) for n in range(
				len(allUsersList)
			)]

			dbManager.openDB("mydb")
			for name in allUsersList:
				dbManager.addNameToUserTable(name)

			Page = open(os.path.join('static', 'main.html'))

		except (KeyError, ValueError):  # There is no username
			Page = open(os.path.join('static', 'index.html'))
		return Page



	# LOGGING IN AND OUT ------------------------------------------------------------
	@cherrypy.expose
	def login(self):
		loginpath = os.path.join('static', 'login.html')
		Page = open(loginpath)

		return Page

	@cherrypy.expose
	def signin(self, username=None, password=None, twofac=0):
		"""Check their name and password and send them either to the main page, or back to the main login screen."""
		hashPass = sha256(password + username)
		hexPass = hashPass.hexdigest()

		if int(twofac) == self.get_totp_token(base64.b32encode(username + "bas")) or dbManager.getTwoFacEnabled(username) == 0:
			pass
		else:
			print "2FA error"
			print type(self.get_totp_token(username + "bas"))
			print type(twofac)
			raise cherrypy.HTTPRedirect('/')

		error = self.loginToServer(username, hexPass)

		if (error[0] == "0"):
			cherrypy.session['username'] = username
			cherrypy.session['password'] = hexPass
			raise cherrypy.HTTPRedirect('/')
		else:
			print error
			raise cherrypy.HTTPRedirect('/login')

	@cherrypy.expose
	@atexit.register
	def signout(self):
		"""Logs the current user out, expires their session"""
		username = cherrypy.session.get('username')
		password = cherrypy.session.get('password')
		url = "http://cs302.pythonanywhere.com/logoff"
		data = {'username' : username, 'password' : password, 'enc' : 0}

		if username is None:
			print "not logged in"
			pass
		else:
			post = urlencode(data)
			req = urllib2.Request(url, post)
			resp = urllib2.urlopen(req).read()
			del cherrypy.session['username']
			del cherrypy.session['password']
			cherrypy.lib.sessions.expire()

		raise cherrypy.HTTPRedirect('/')


	def loginToServer(self, username, hexPass):
		url = "http://cs302.pythonanywhere.com/report"
		my_ip = urllib2.urlopen('http://ip.42.pl/raw').read()	  # public IP
		# my_ip = socket.gethostbyname(socket.gethostname())  # local IP
		my_port = 10005
		cherrypy.session['ip'] = my_ip
		data = {'username': username, 'password': hexPass, "location": 2, 'ip': my_ip, 'port': my_port}
		post = urlencode(data)
		req = urllib2.Request(url, post)
		response = urllib2.urlopen(req)

		return response.read()

 	# Messaging -------------------------------------------------------------------
	@cherrypy.expose
	def ping(self, sender):
		return '0'

	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveMessage(self):
		input_data = cherrypy.request.json
		senderName = input_data['sender']
		newMessage = input_data['message']
		stamp = input_data['stamp']
		destination = input_data['destination']
		dbManager.addMessage(senderName, newMessage, stamp, destination)

		return '0'

	@cherrypy.expose
	@cherrypy.tools.json_out()
	def sendMessage(self, message=None):
		recipient = cherrypy.session.get('recipient')
		username = cherrypy.session.get('username')
		currentTime = str(calendar.timegm(time.gmtime()))

		dataToPost = {'sender': username, 'message': message, 'destination': recipient, 'stamp': currentTime}
		url = dbManager.getUserIP(recipient)
		port = dbManager.getUserPort(recipient)
		url = "http://" + url + ":" + port + "/receiveMessage"
		url = url.encode('ascii', 'ignore')

		print "Attempted Url is: " + url
		print "Attempted Data is: "
		print dataToPost

		post = json.dumps(dataToPost)
		req = urllib2.Request(url)
		req.add_header('Content-Type', 'application/json')
		response = urllib2.urlopen(req, post)

		if response.read() == '0' and recipient != username:
			dbManager.addMessage(username, message, currentTime, recipient)
		# return '0'
		raise cherrypy.HTTPRedirect('/')

	# FILES ---------------------------------------------------------------------
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveFile(self):
		input_data = cherrypy.request.json
		sender = input_data['sender']
		destination = input_data['destination']
		encodedfile = input_data['file']
		filename = input_data['filename']
		content_type = input_data['content_type']
		stamp = input_data['stamp']
		# path = os.path.join(current_dir, 'db')

		decodedfile = encodedfile.decode('base64')
		savefile = open(filename, 'wb')
		savefile.write(decodedfile)

		return '0'


	@cherrypy.expose
	@cherrypy.tools.json_out()
	def sendFile(self, myFile):
		data = myFile.file.read()
		mime = MimeTypes()
		fileurl = urllib.pathname2url(myFile.filename)
		mime_type = mime.guess_type(fileurl)
		sender = cherrypy.session.get('username')
		destination = cherrypy.session.get('recipient')
		stamp = str(calendar.timegm(time.gmtime()))
		data = data.encode('base64')

		post = {'sender': sender, 'destination': destination, 'stamp': stamp, 'file': data, 'filename': myFile.filename, 'content_type': mime_type[0]}
		post = json.dumps(post)
		url = dbManager.getUserIP(destination)
		port = dbManager.getUserPort(destination)
		url = "http://" + url + ":" + port + "/receiveFile"
		url = url.encode('ascii', 'ignore')
		req = urllib2.Request(url)
		req.add_header('Content-Type', 'application/json')
		response = urllib2.urlopen(req, post)
		print "Send File response is:" + response.read()
		raise cherrypy.HTTPRedirect('/')

	#Profiles---------------------------------------------------------------
	@cherrypy.expose
	def getProfile(self, profile_username, sender):
		fullname = 'NA'
		position = 'NA'
		description = 'NA'
		location = 'NA'
		profileData = dbManager.readProfile(profile_username)

		if dbManager.getLastUpdated(profile_username) is None:
			lastUpdated = 0

		else:
			lastUpdated = dbManager.getLastUpdated(profile_username)
			fullname = profileData[1]
			position = profileData[2]
			description = profileData[3]
			location = profileData[4]
		
		response = {'lastUpdated': lastUpdated, 'fullname': fullname, 'position': position, 'description': description, 'location': location}
		response = json.dumps(response)

		return response

	@cherrypy.expose
	def updateProfile(self, fullname="None"):
		raise cherrypy.HTTPRedirect('/')

	@cherrypy.expose
	def inspectProfile(self, profile):
		url = dbManager.getUserIP(profile)
		port = dbManager.getUserPort(profile)
		url = "http://" + url + ":" + port + "/getProfile?profile_username=%s&sender=%s" % (profile, cherrypy.session.get('username'))
		#p ost = {'profile_username': profile, 'sender': cherrypy.session.get('username')}
		# post = json.dumps(post)
		print url
		req = urllib2.Request(url)
		response = urllib2.urlopen(req)
		response = json.loads(response.read())

		if int(response['lastUpdated']) > dbManager.getLastUpdated(profile):
			if response['lastUpdated'] is not None:
				lastUpdated = response['lastUpdated']

			if response['fullname'] is not None:
				fullname = response['fullname']

			if response['position'] is not None:
				lastUpdated = response['position']

			if response['description'] is not None:
				description = response['description']

			if response['location'] is not None:
				location = response['location']

			if response['picture'] is not None:
				picture = response['picture']
			dbManager.addProfile(profile, response['lastUpdated'], lastUpdated, fullname, description,location,picture)
		else:
			profileData = dbManager.readProfile(profile)

		page = ''
		if profileData == "NA":
			page = "Profile not available"
		elif profile == cherrypy.session.get('username'):
			page += "<form action='updateProfile' method='post' enctype='multipart/form-data'>"
			page += "Full Name: <input type='text' name='fullname' value='"+ profileData[2] +"'>"
			page +=	"Position: <input type='text' name='position' value='" + profileData[3] + "'>"
			page += "Description: <input type='text' name='description' value='" + profileData[4] + "'>"
			page += "Location: <input type='text' name='location' value='" + profileData[5] + "'>"
			page += "<input type='submit' value='Update Profile'>"
			page += "</form>"
		else:

			page += "Full Name: " + profileData[2]
			page += "Position: " + profileData[3]
			page += "Description: " + profileData[4]
			page += "Location: " + profileData[5]
		return page

	#Backend methods -------------------------------------------------------
	@cherrypy.expose
	def updateUserList(self, parameter):
		username = cherrypy.session.get('username')
		if username is not None:
			reportUrl = urllib2.Request('http://cs302.pythonanywhere.com/report')
			userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
			data = {'username': cherrypy.session.get('username'), 'password': cherrypy.session.get('password'), 'enc': 0,
					'json': 1,'location': 2, 'port': 10005, 'ip': cherrypy.session.get('ip')}
			post = urlencode(data)
			userList = urllib2.urlopen(userListUrl, post)
			report = urllib2.urlopen(reportUrl, post)
			jsonUserList = userList.read()
			jsonUserList = json.loads(jsonUserList)
			# print report.read()
			onlineUsers = list()
			replyString = "<ul>"
			for id in jsonUserList:
				onlineUsers.append(str(jsonUserList[id][parameter]))

			onlineUsers.sort()

			for user in onlineUsers:
				replyString += "<li>" + "<a href=javascript:pullMessages('" + user + "');>" + user + "</a> <a href='/inspectProfile?profile="+ user +  "'> Profile" "</a></li>"

			replyString += "</ul>"
			return replyString
		else:
			return "Not logged in"

	# HTML helpers ----------------------------------------------------------
	@cherrypy.expose
	def inbox(self, sender):
		if cherrypy.session.get('username') is None:
			Page = "Not logged in"

		elif sender == 'None':
			Page = ""

		else:
			cherrypy.session['recipient'] = sender
			Page = dbManager.readMessages(sender)

		return Page

	@cherrypy.expose
	def currentChat(self):		
		if cherrypy.session.get('recipient') is None:
			# print "No conversation selected"
			return "None"
		else:
			# print "Trying to retrieve conversation with: " + cherrypy.session.get('recipient')
			return cherrypy.session.get('recipient')

	@cherrypy.expose
	def getSecret(self):
		if cherrypy.session.get('username') is None:
			return "0"
		else:
			username = cherrypy.session.get('username')
			key  = base64.b32encode(username + "bas")
			self.enable2FA()
			print key
			return key

	@cherrypy.expose
	def enable2FA(self):
		dbManager.setTwoFacEnabled(cherrypy.session.get('username'), 1)
		print "2FA enabled"
		return '0'

	# Two Factor Authentication ----------------------------------------------
	def get_hotp_token(self, secret, intervals_no):
		key = base64.b32decode(secret, True)
		msg = struct.pack(">Q", intervals_no)
		h = hmac.new(key, msg, hashlib.sha1).digest()
		o = ord(h[19]) & 15
		h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
		return h

	def get_totp_token(self, secret):
		intervals_no = int(time.time()) // 30
		return self.get_hotp_token(secret, intervals_no)

def runMainApp():
	# Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
	app = cherrypy.tree.mount(MainApp(), "/",{'/': {'tools.staticdir.root': current_dir},
							'/static': {
								'tools.staticdir.on': True, #,
								'tools.staticdir.dir': "static"
								}}) 		# , "app.conf")
	app.log.access_log.addFilter(IgnoreURLFilter('updateUserList'))
	app.log.access_log.addFilter(IgnoreURLFilter('currentChat'))
	app.log.access_log.addFilter(IgnoreURLFilter('inbox'))

	# Tell Cherrypy to listen for connections on the configured address and port.
	cherrypy.config.update({'server.socket_host': listen_ip,
							'server.socket_port': listen_port,
							'engine.autoreload.on': True,
							})

	print "========================="
	print "University of Auckland"
	print "COMPSYS302 - Software Design Application"
	print "========================================"

	# Start the web server
	cherrypy.engine.start()

	# And stop doing anything else. Let the web server take over.
	cherrypy.engine.block()


# Run the function to start everything
runMainApp()
