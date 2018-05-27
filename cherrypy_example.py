#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2018

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10005

import cherrypy
from hashlib import sha256
from urllib import urlencode
import urllib
import urllib2
import socket
import os.path
import sqlite3
import json
import dbManager
import atexit
import calendar
import time
import logging
from mimetypes import MimeTypes


current_dir = os.path.dirname(os.path.abspath(__file__))


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
        Page = "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = "Welcome! This is a test website for COMPSYS302!<br/>"
        try:
            userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
            data = {'username': cherrypy.session.get('username'), 'password': cherrypy.session.get('password'), 'enc' : 0, 'json' : 1}
            post = urlencode(data)
            response = urllib2.urlopen(userListUrl, post)
            resp = response.read()
            print resp
            jsonUserList = json.loads(resp)

            dbManager.openDB("mydb")
            dbManager.addToUserTable("mydb", jsonUserList)
            # dbManager.readUserTable("mydb")

            Page = open(os.path.join('static', 'main.html'))

        except (KeyError, ValueError):  # There is no username
            Page = open(os.path.join('static', 'index.html'))
        return Page

    #Backend methods
    @cherrypy.expose
    def updateUserList(self, parameter):
        username = cherrypy.session.get('username')
        if(username != None):
            reportUrl = urllib2.Request('http://cs302.pythonanywhere.com/report')
            userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
            data = {'username': cherrypy.session.get('username'), 'password': cherrypy.session.get('password'), 'enc': 0,
                    'json': 1,'location': 2, 'port': 10005, 'ip': cherrypy.session.get('ip')}
            post = urlencode(data)
            userList = urllib2.urlopen(userListUrl, post)
            # data.update({'location': 2, 'port': 10005})
            # post = urlencode(data)
            report = urllib2.urlopen(reportUrl, post)
            jsonUserList = userList.read()
            jsonUserList = json.loads(jsonUserList)


            replyString = "<ul>"
            for id in jsonUserList:
                user = jsonUserList[id][parameter]
                replyString += "<li>" + "<a href=javascript:pullMessages('" + user + "');>" + jsonUserList[id][parameter] + "</a></li>"

            replyString += "</ul>"
            return replyString

        else:
            return "Not logged in"

    @cherrypy.expose
    def login(self):
        loginpath = os.path.join('static', 'login.html')
        Page = open(loginpath)

        return Page

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        hashPass = sha256(password + username)
        hexPass = hashPass.hexdigest()
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
        my_ip = urllib2.urlopen('http://ip.42.pl/raw').read()      # public IP
        # my_ip = socket.gethostbyname(socket.gethostname())  # local IP
        my_port = 10005
        cherrypy.session['ip'] = my_ip
        data = {'username': username, 'password': hexPass, "location": 2, 'ip': my_ip, 'port': my_port}
        post = urlencode(data)
        req = urllib2.Request(url, post)
        response = urllib2.urlopen(req)

        return response.read()

    @cherrypy.expose
    def ping(self, sender):
        # input_data = cherrypy.request.json
        # raise cherrypy.HTTPRedirect('/')
        return '0'

    # Messaging
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

    # FILES
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

    @cherrypy.expose
    def messages(self, sender):
        if cherrypy.session.get('username') is None:
            Page = "Not logged in"
        else:
            Page = open(os.path.join('static', 'messages.html'))

        return Page

	# Retrieves Message History
    @cherrypy.expose
    def inbox(self, sender):
        if cherrypy.session.get('username') is None:
            Page = "Not logged in"

        elif sender == 'None':
            Page = "Choose a user to start chatting"

        else:
            cherrypy.session['recipient'] = sender
            Page = dbManager.readMessages(sender)

        return Page

    @cherrypy.expose
    def currentChat(self):
        if cherrypy.session.get('recipient') is None:
            return "None"
        else:
            return cherrypy.session.get('recipient')

def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    app = cherrypy.tree.mount(MainApp(), "/", "app.conf")
    app.log.access_log.addFilter(IgnoreURLFilter('updateUserList'))
    app.log.access_log.addFilter(IgnoreURLFilter('currentChat'))
    app.log.access_log.addFilter(IgnoreURLFilter('inbox'))

    # Tell Cherrypy to listen for connections on the configured address and port.
    cherrypy.config.update({'server.socket_host': listen_ip,
                            'server.socket_port': listen_port,
                            'engine.autoreload.on': True
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
