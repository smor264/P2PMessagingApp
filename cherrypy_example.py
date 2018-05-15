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
listen_port = 1234

import cherrypy
from hashlib import sha256
import json
import httplib
from urllib import urlencode
import urllib2
from urllib2 import urlopen
import socket


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
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Login successful!"
            Page += "<br/> Additional text from sam."
            Page += 'Online Users: '
            userListUrl = urllib2.Request('http://cs302.pythonanywhere.com/getList')
            data = {'username' : cherrypy.session.get('username'), 'password' : cherrypy.session.get('password'), 'enc' : 0 }
            post = urlencode(data)
            response = urllib2.urlopen(userListUrl, post)
            Page += response.read()

        except KeyError:  # There is no username
            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self):
        Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

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
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if (username == None):
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


    def loginToServer(self, username, hexPass):
        url = "http://cs302.pythonanywhere.com/report"
        #my_ip = urlopen('http://ip.42.pl/raw').read        #public IP
        my_ip = socket.gethostbyname(socket.gethostname()) #local IP
        my_port = 10005

        data = {'username' : username, 'password' : hexPass, "location" : 1, 'ip' : my_ip, 'port' : my_port}
        post = urlencode(data)
        req = urllib2.Request(url, post)
        response = urllib2.urlopen(req)

        return response.read()




def runMainApp():
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(MainApp(), "/")

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
