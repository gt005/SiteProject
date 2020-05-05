from flask import Flask, request, g, abort, render_template, url_for, redirect, make_response
from globalVariable import *
from app import app
import bcrypt
import re
import mysql.connector


data_base = mysql.connector.connect(
    host='localhost',
    user='root',
    passwd='gt005gt005',
    database='sitedb'
)

db_cursor = data_base.cursor()


def verify_password_on_correct(**verifiable):
    """ dict([str key: str element],) -> dict([str key: bool],)
        Проверяет, нет ли в строке лишних символов.
        В конце возвращает словарь, где каждому ключу соответвует занчение,
        подходит ли строка или нет.
    """
    result = dict()
    expression = re.compile(r'[a-zA-Z0-9_]{5,15}$')
    for key, element in verifiable.items():
        if expression.match(element):
            result[key] = True
        else:
            result[key] = False
    return result


def accessing_the_database(query, changes=False):
    db_cursor.execute(query)
    if changes:
        data_base.commit()
        return None
    return db_cursor.fetchall()


@app.route('/')
def index():
    return render_template('index.html', session=True)


@app.route('/login', methods=['post', 'get'])
def login():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        if not username and password:
            message = 'Empty login or password.'
        elif accessing_the_database(QUERY_COMMANDS['check_username'] % username)[0][0] == 0:  # count(username)
            message = 'User does not exist.'
        elif not all(verify_password_on_correct(username=username, password=password).values()):
            message = PASSWORD_FORM
        else:
            result = accessing_the_database(QUERY_COMMANDS['get_password'] % username)
            if bcrypt.checkpw(bytes(password, encoding='utf-8'), result[0][0]):
                return redirect(url_for('index'))  # TODO: Генерировать тут сессию
            else:
                message = 'Wrong password.'
    return render_template('login.html', message=message, session=True)


@app.route('/registration', methods=['post', 'get'])
def registration():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        rep_password = str(request.form.get('rep_password'))
        if not username and password and rep_password:
            message = 'Empty login or one of passwords.'
        elif accessing_the_database(QUERY_COMMANDS['check_username'] % username)[0][0] != 0:  # count(username)
            message = 'User with the same name already exist.'
        elif not all(verify_password_on_correct(
                username=username, password=password,
                rep_password=rep_password).values()):
            message = PASSWORD_FORM
        elif rep_password != password:
            message = 'Passwords are not equal.'
        else:
            accessing_the_database(QUERY_COMMANDS['add_user'] \
            % (username, bcrypt.hashpw(bytes(password, encoding='utf-8'),
                        bcrypt.gensalt()).decode('utf-8')), changes=True)
            return redirect(url_for('index'))  # TODO: Генерировать тут сессию
    return render_template('registration.html', message=message, session=True)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', session=True)

@app.route('/403')
@app.errorhandler(403)
def page_not_found():
    return render_template('403.html', session=True)


@app.route('/about-us')
def about_us():
    return render_template('about-us.html', session=True)


@app.route('/videos')
def videos():
    return render_template('videos.html', session=True, listOfVideos={
        '1': 'index', '2': 'login', '3': 'registration',
        '4': 'login', '5': 'login', '6': 'login',
        '7': 'login', '8': 'login', '9': 'login'})


if __name__ == "__main__":
    app.run(debug=True)