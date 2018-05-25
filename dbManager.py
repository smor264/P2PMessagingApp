import sqlite3
import json

# Opens or creats a database with the name passed in
def openDB(mydb):
    db = sqlite3.connect('db/' + mydb)
    cursor = db.cursor()
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, location TEXT,
                                    IP TEXT, port TEXT, lastlogin INTEGER)''')
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS messages(messageID TEXT PRIMARY KEY, sender TEXT,
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

def addMessage(senderName, newMessage, stamp):
    try:
        db = sqlite3.connect('db/mydb')
        cursor = db.cursor()

        # Check for duplicate messages
        messID = senderName + newMessage

        # Add the message
        try:
            cursor.execute('''
                INSERT INTO messages(messageID, sender, messages, stamp) VALUES(?,?,?,?)''', (messID, senderName, newMessage, stamp))
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
        messageLog = 'Messages from ' + sender + ': <br/>'
        cursor.execute('''SELECT messages, stamp FROM messages WHERE sender=?''', (sender,))
        all_rows = cursor.fetchall()
        for row in all_rows:
            print row
            messageLog += row[0] + " " + row[1] + "<br/>"

    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()
        return messageLog

def getUserDetails(user, details):
    try:
        db = sqlite3.connect('db/mydb')
        cursor = db.cursor()
        cursor.execute('''SELECT ? FROM users WHERE name=?''', (details, user))
        output = cursor.fetchall()
    except Exception as e:
        output = "Not Available"
        db.rollback()
        raise e
    finally:
        db.close()
        return output