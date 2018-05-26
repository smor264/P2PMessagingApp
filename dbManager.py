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
                    CREATE TABLE IF NOT EXISTS messages(messageID TEXT PRIMARY KEY, sender TEXT, destination TEXT,
                                    messages TEXT, stamp TEXT)''')
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

        # Check for duplicate messages
        messID = newMessage+stamp+senderName

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
            messageLog += row[0] + " " + row[1] + "<br/>"

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
