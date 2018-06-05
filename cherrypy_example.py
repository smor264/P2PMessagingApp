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
import socket
import threading
from threading import Timer, Thread, Event

current_dir = os.path.dirname(os.path.abspath(__file__))

class MyThread(Thread):
	def __init__(self, event):
		Thread.__init__(self)
		self.stopped = event
		self.username = ''
		self.password = ''
		self.ip = ''

	def run(self):
		while not self.stopped.wait(30.0):
			MainApp().reportToServer(self.username, self.password, self.ip)

	def updateDetails(self, username, password, ip):
		self.username = username
		self.password = password
		self.ip = ip

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

	stopFlag = Event()

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
			stopFlag = Event()
			thread.updateDetails(cherrypy.session.get('username'), cherrypy.session.get('password'), cherrypy.session.get('ip'))

			userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
			data = {'username': cherrypy.session.get('username'), 'password': cherrypy.session.get('password'), 'enc' : 0, 'json' : 1}
			post = urlencode(data)
			response = urllib2.urlopen(userListUrl, post)
			resp = response.read()
			# print resp
			jsonUserList = json.loads(resp)
			# print resp

			dbManager.openDB("mydb")
			#dbManager.addToUserTable(jsonUserList)
			#dbManager.readUserTable("mydb")
			
			if cherrypy.session.get('username') is None:
				Page = open(os.path.join('static', 'index.html'))
				return Page

			url = urllib2.Request('http://cs302.pythonanywhere.com/listUsers')
			response = urllib2.urlopen(url).read()

			allUsersList = response.split(',')

			
			# print allUsersList
			dbManager.openDB("mydb")
			for name in allUsersList:
				dbManager.addNameToUserTable(name)

			Page = open(os.path.join('static', 'main.html'))

		except (KeyError, ValueError):  # There is no username
			Page = open(os.path.join('static', 'index.html'))
			stopFlag.set()
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
		dbManager.openDB('mydb')
		hashPass = sha256(password + username)
		hexPass = hashPass.hexdigest()
		
		if dbManager.getTwoFacEnabled(username) is not None:
			print "this users 2FA status is" + str(dbManager.getTwoFacEnabled(username)[0])
			if dbManager.getTwoFacEnabled(username)[0] == 1:
				if int(twofac) == self.get_totp_token(base64.b32encode(username + "bas")):
					cherrypy.log("2FA success")
					pass
				else:
					cherrypy.log("2FA error")
					raise cherrypy.HTTPRedirect('/')
			else:
				pass

		error = self.loginToServer(username, hexPass)

		if (error[0] == "0"):
			cherrypy.session['username'] = username
			cherrypy.session['password'] = hexPass
			raise cherrypy.HTTPRedirect('/')
		else:
			cherrypy.log("Error Logging in. Code: " + error)
			raise cherrypy.HTTPRedirect('/login')

	@cherrypy.expose
	def signout(self, thread):
		"""Logs the current user out, expires their session"""
		SignOutUsername = cherrypy.session.get('username')
		SignOutPassword = cherrypy.session.get('password')
		url = "http://cs302.pythonanywhere.com/logoff"
		data = {'username' : SignOutUsername, 'password' : SignOutPassword, 'enc' : 0}

		if SignOutUsername is None:
			cherrypy.log("not logged in")
			pass
		else:
			post = urlencode(data)
			req = urllib2.Request(url, post)
			resp = urllib2.urlopen(req).read()

			del cherrypy.session['username']
			del cherrypy.session['password']
			cherrypy.lib.sessions.expire()
			print "Logged Off Successfully"

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

		cherrypy.log("Attempted Url is: " + url)
		cherrypy.log("Attempted Data is: ")
		cherrypy.log(str(dataToPost))

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
		cherrypy.log("Send File response is:" + response.read())
		raise cherrypy.HTTPRedirect('/')

	#Profiles---------------------------------------------------------------
	#GET PROFILE
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getProfile(self):
		print "________--------_____ We made it to getProfile"
		input_data = cherrypy.request.json
		profile_username = input_data['profile_username']
		sender = input_data['sender']
		fullname = 'NA'
		position = 'NA'
		description = 'NA'
		location = 'NA'
		picture = 'NA'
		lastUpdated = 0

		profileData = dbManager.readProfile(profile_username)
		print "The profile data for " + profile_username + " is: " + str(profileData)
		print "The Last Updated field is" + str(dbManager.getLastUpdated(profile_username))
		
		if dbManager.getLastUpdated(profile_username) is None:
			lastUpdated = 0
		elif dbManager.getLastUpdated(profile_username)[0] != 0:
			print "Using the Up-to-date profile"
			lastUpdated = dbManager.getLastUpdated(profile_username)
			fullname = profileData[0][1]
			position = profileData[0][2]
			description = profileData[0][3]
			location = profileData[0][4]
			picture = profileData[0][5]
		
		print "Sending the response"
		response = {'lastUpdated': lastUpdated, 'fullname': fullname, 'position': position, 'description': description, 'location': location}
		response = json.dumps(response)

		return response
	
	#UPDATE PROFILE
	@cherrypy.expose
	def updateProfile(self, fullname, position, description, location, myFile):
		lastUpdated = int(calendar.timegm(time.gmtime()))
		myFile = myFile.read()
		user = cherrypy.session.get('username')
		print "-------------------------------------User is: " + user
		print "fullname is: " + fullname
		print "file name is: " + myFile
		dbManager.addProfile(user, lastUpdated, fullname, position, description, location, myFile) 
		raise cherrypy.HTTPRedirect('/')
	
	#INSPECT PROFILE
	@cherrypy.expose
	def inspectProfile(self, profile):
		url = dbManager.getUserIP(profile)
		port = dbManager.getUserPort(profile)
		url = "http://" + url + ":" + port
		url1 = url + "/getProfile"
		post = {'profile_username': profile, 'sender': cherrypy.session.get('username')}
		post = json.dumps(post)
		req = urllib2.Request(url1)
		req.add_header('Content-Type', 'application/json')
		response = urllib2.urlopen(req, post)
		response = json.loads(response.read())
			
		lastUpdated = response.get('lastUpdated')
		fullname = response.get('fullname')
		position = response.get('position')
		description = response.get('description')
		location = response.get('location')
		picture = response.get('picture')

		dbManager.addProfile(profile, lastUpdated, fullname, position, description, location, picture)

		profileData = dbManager.readProfile(profile)
		print "Profile data is: " + str(profileData)
		page = ''
		if profile == cherrypy.session.get('username'):
			page += "<form action='/updateProfile' method='post' enctype='multipart/form-data'><br/>"
			page += "Full Name: <input type='text' name='fullname' value='"+ fullname +"'><br/>"
			page +=	"Position: <input type='text' name='position' value='" + position + "'><br/>"
			page += "Description: <input type='text' name='description' value='" + description + "'><br/>"
			page += "Location: <input type='text' name='location' value='" + location + "'><br/>"
			page += "Picture: <input type='image' name='image' value='choose an image'>"
			page += "<input type='file' name='myFile' maxlength=50 allow='image/*'>"
			page += "<input type='submit' value='Update Profile'>"
			page += "</form>"
		else:

			page += "Full Name: " + str(fullname) + "</br>"
			page += "Position: " + str(position) + "</br>"
			page += "Description: " + str(description) + "</br>"
			page += "Location: " + str(location) + "</br>"

		# Save a local copy of the profile picture
		try:
			response = urllib2.urlopen(picture)
			pic = response.read()
			savedpic = open("profiles/" + profile, "wb")
			savedpic.write(pic)
			page += "Picture: <img src='/profiles/" + profile + "'>"
		#else use a default placeholder
		except AttributeError as e:
			page += "Picture: <img src='static/default.png' >"
			
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
			report = report.read()
			dbManager.addToUserTable(jsonUserList)
			onlineUsers = list()
			replyString = "<ul>"
			for id in jsonUserList:
				onlineUsers.append(str(jsonUserList[id][parameter]))

			onlineUsers.sort()
			allUsers = dbManager.getAllUsers()
			listAllUsers = list()

			for i in allUsers:
				listAllUsers.append(i[0])

			for user in onlineUsers:
				replyString += "<li>" + "<a href=javascript:pullMessages('" + user + "');>" + user + "</a> <a href='/inspectProfile?profile="+ user +  "'> Profile" "</a></li>"
			for i in listAllUsers:
				if i not in onlineUsers:
					replyString += "<li>" + "<b href=javascript:pullMessages('" + i + "');>" + i + "</b> <b href='/inspectProfile?profile="+ i +  "'> Profile" "</b></li>"
			replyString += "</ul>"
			return replyString
		else:
			return "Not logged in"

	def reportToServer(self, username, password, ip):
		if cherrypy.engine.state != cherrypy.engine.states.STARTED:
			return

		if username is not None:
			reportUrl = urllib2.Request('http://cs302.pythonanywhere.com/report')
			data = {'username': username, 'password': password, 'enc': 0,
					'json': 1, 'location': 2, 'port': 10005, 'ip': ip}
			post = urlencode(data)
			report = urllib2.urlopen(reportUrl, post)
			print "Report Complete, Response: " + report.read()
		else:
			print "Failed to Report"
		return

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
			return cherrypy.session.get('recipient')

	@cherrypy.expose
	def getSecret(self):
		if cherrypy.session.get('username') is None:
			print "no username"
			return "0"
		else:
			username = cherrypy.session.get('username')
			key  = base64.b32encode(username + "bas")
			self.enable2FA()
			print "2FA status is: " + str(dbManager.getTwoFacEnabled(username)[0])
			return key

	@cherrypy.expose
	def enable2FA(self):
		username = cherrypy.session.get('username')
		# print "2FA status is: " + str(dbManager.getTwoFacEnabled(username)[0])
		# if dbManager.getTwoFacEnabled(username)[0] == 1:
		# 	dbManager.setTwoFacEnabled(username, 0)
		#	print "2FA disabled"
		# else:
		dbManager.setTwoFacEnabled(username, 1)

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

	# Signout on application close
	def exit_handler(self):
		self.signout()
		print "Signing Off"

def runMainApp():
	# Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
	server = MainApp()
	app = cherrypy.tree.mount(server, "/",{'/': {'tools.staticdir.root': current_dir},
							'/static': {
								'tools.staticdir.on': True, 
								'tools.staticdir.dir': "static"
							}, '/profiles': {
									'tools.staticdir.on': True,
									'tools.staticdir.dir': "profiles"
								}}) 		
	app.log.access_log.addFilter(IgnoreURLFilter('updateUserList'))
	app.log.access_log.addFilter(IgnoreURLFilter('currentChat'))
	app.log.access_log.addFilter(IgnoreURLFilter('inbox'))

	# Tell Cherrypy to listen for connections on the configured address and port.
	cherrypy.config.update({'server.socket_host': listen_ip,
							'server.socket_port': listen_port,
							'engine.autoreload.on': True,
							'log.access_file' : "access.log",
							'log.error_file' : "error.log",
							'log.screen' : True
							})

	print "========================="
	print "University of Auckland"
	print "COMPSYS302 - Software Design Application"
	print "========================================"


	# Start the web server
	cherrypy.engine.start()

	# And stop doing anything else. Let the web server take over.
	cherrypy.engine.block()

	stopFlag = Event()
	thread = MyThread(stopFlag)
	atexit.register(server.signout())

# Run the function to start everything
runMainApp()
