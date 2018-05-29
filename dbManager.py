import sqlite3
import json
import cherrypy

# Opens or creats a database with the name passed in
def openDB(mydb):
	db = sqlite3.connect('db/' + mydb)
	cursor = db.cursor()
	cursor.execute('''
					CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, location TEXT,
									IP TEXT, port TEXT, lastlogin INTEGER)''')
	cursor.execute('''
					CREATE TABLE IF NOT EXISTS messages(messageID TEXT PRIMARY KEY, sender TEXT, 				destination TEXT, messages TEXT, stamp INTEGER)''')

	cursor.execute('''
		CREATE TABLE IF NOT EXISTS profiles(name TEXT PRIMARY KEY, lastUpdated INTEGER, fullname TEXT, position TEXT, description TEXT, location TEXT)''')

	db.commit()
	db.close()

def addToUserTable(myDB, jsonUserList):
	try:
		db = sqlite3.connect('db/' + myDB)
		cursor = db.cursor()
		for id in jsonUserList:
			name = jsonUserList[id]['username']
			ip = jsonUserList[id]['ip']
			port = jsonUserList[id]['port']
			location = jsonUserList[id]['location']
			lastLogin = jsonUserList[id]['lastLogin']
			tableName = 'users'
			cursor.execute('''
							INSERT OR REPLACE INTO users(name, location, IP, port, lastlogin)
										VALUES(?,?,?,?,?)''', (name, location, ip, port, lastLogin))
		db.commit()
	except Exception as e:
		db.rollback()
		raise e
	finally:
		db.close()

def addMessage(senderName, newMessage, stamp, destination):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		stampString = str(stamp)

		# Check for duplicate messages
		messID = newMessage+stampString+senderName

		stamp = int(stamp)
		print type(stamp)

		# Add the message
		try:
			cursor.execute('''
				INSERT INTO messages(messageID, sender, destination, messages, stamp) VALUES(?,?,?,?,?)''', (messID, senderName, destination, newMessage, stamp))
			db.commit()
		except Exception as e:
			print 'Duplicate message'
			raise e

	except Exception as e:
		db.rollback()
		raise e
	finally:
		db.close()

def addProfile(name, lastUpdated, fullName='--', position='--', description='--', location='--'):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		cursor.execute('''INSERT OR REPLACE INTO profiles(name, lastUpdated, fullname, position, 	description, location) VALUES(?,?,?,?,?,?)''', (name, lastUpdated, fullName, position, description, location))
	
	except Exception as e:
		db.rollback()
		raise e
	finally:
		db.close()

def readProfile(name):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		data = tuple()

		cursor.execute('''SELECT lastUpdated, fullname, position, description, location FROM profiles WHERE name = ?''', (name,))	
		data = cursor.fetchall()

	except ValueError as e:
		print "Name does not exist in database"
		raise e

	finally:
		db.close()
		return data

def getLastUpdated(name):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		cursor.execute('''SELECT lastUpdated FROM profiles WHERE name=? ''', (name,))
		lastUpdated = cursor.fetchone()
	
	except Exception as e:
		db.rollback()
		raise e
	finally:
		db.close()
		return lastUpdated

def readUserTable(myDB):
	try:
		db = sqlite3.connect('db/' + myDB)
		cursor = db.cursor()
		cursor.execute('''SELECT name, location, IP, port, lastlogin FROM users''')
		user1 = cursor.fetchone()
		print user1[0]
		all_rows = cursor.fetchall()
		for row in all_rows:
			print row

	except Exception as e:
		raise e
	finally:
		db.close()

def readMessages(sender):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		user = cherrypy.session.get('username')
		messageLog = 'Messages from ' + sender + ': <br/>'
		cursor.execute('''SELECT messages, stamp FROM messages WHERE (sender=? AND destination=?) OR (destination=? AND sender=?)''', (sender, user, sender, user))
		all_rows = cursor.fetchall()
		for row in all_rows:
			# print row
			messageLog += row[0] + " " + str(row[1]) + "<br/>"

	except Exception as e:
		db.rollback()
		raise e
	finally:
		db.close()
		return messageLog

def getUserIP(user):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		cursor.execute('''SELECT IP FROM users WHERE name=?''', (user,))
		output = cursor.fetchone()
	except ValueError as e:
		output = "Not Available"
		print "Detail not found"
		db.rollback()
		raise e
	finally:
		db.close()
		return output[0]

def getUserPort(user):
	try:
		db = sqlite3.connect('db/mydb')
		cursor = db.cursor()
		cursor.execute('''SELECT port FROM users WHERE name=?''', (user,))
		output = cursor.fetchone()
	except ValueError as e:
		output = "Not Available"
		print "Detail not found"
		db.rollback()
		raise e
	finally:
		db.close()
		return output[0]
