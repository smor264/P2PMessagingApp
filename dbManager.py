import sqlite3
import json

# Opens or creats a database with the name passed in
def openDB(mydb):
    db = sqlite3.connect('db/' + mydb)
    cursor = db.cursor()
    cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, location TEXT,
                                    IP TEXT, port TEXT, lastlogin INTEGER, messages TEXT)''')
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
            cursor.execute('''
                            INSERT OR REPLACE INTO users(name, location, IP, port, lastlogin)
                                        VALUES(?,?,?,?,?)''', (name, location, ip, port, lastLogin))
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def addMessage(senderName, newMessage):
    try:
        db = sqlite3.connect('db/mydb')
        cursor = db.cursor()

        # check if table already exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS ''' + senderName + '''(messID INTEGER PRIMARY KEY, sender TEXT, message TEXT,
                    stamp INTEGER)''')

        # Add the message
        cursor.execute('''
                INSERT INTO ''' + senderName + '''(sender, message) VALUES(?,?)''', (senderName, newMessage))

        all_rows = cursor.fetchall()
        print "Current message database"
        for row in all_rows:
            print row


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



