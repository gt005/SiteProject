import mysql.connector
import bcrypt
password = b'admin'
data_base = mysql.connector.connect(
    host='localhost',
    user='root',
    passwd='gt005gt005',
    database='sitedb'
)

db_cursor = data_base.cursor()

queryCommands = {
    'add_user': 'insert into users (username, hashed_password) values (\'%s\', \'%s\');' % ('admin', bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8'))
}
# )
# print(queryCommands['add_user'])
db_cursor.execute('select * from users;')
hashed = db_cursor.fetchall()[0][1]
password = b'admin'

if bcrypt.checkpw(password, hashed):
    print("It Matches!")
else:
     print("It Does not Match :(")

data_base.commit()