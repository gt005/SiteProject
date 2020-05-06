from flask import Flask, request, g, abort, render_template, url_for, redirect, make_response, session
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


class User():
    def __init__(self, *args):
        self.username = args[0]
        self.hashed_password = args[1]
        self.rating_sport = args[2]
        self.rating_creation = args[3]
        self.rating_study = args[4]
        self.role_type = args[5]


class File():
    pass


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


def queryToObject(function):
    # TODO: Придумать нормальное название
    def wrapper(query, *args, changes=False):
        ''' Превращает запрос к бд в объект запрашиваемого типа '''
        if 'from users':
            type_of_object = User
        elif 'from files':
            type_of_object = File
        query = query % args
        db_answer = function(query=query, changes=changes)
        if not changes and db_answer:
            return type_of_object(*(db_answer[0]))
    return wrapper


@queryToObject
def accessing_the_database(query, changes=False):
    db_cursor.execute(query)
    if changes:
        data_base.commit()
        return None
    return db_cursor.fetchall()


def setting_session():
    pass


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['post', 'get'])
def login():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        session.permanent = True
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        if not username and password:
            message = 'Empty login or password.'
        elif accessing_the_database(QUERY_COMMANDS['check_username'], username) is None:  # count(username)
            message = 'User does not exist.'
        elif not all(verify_password_on_correct(username=username, password=password).values()):
            message = PASSWORD_FORM
        else:
            result = accessing_the_database(QUERY_COMMANDS['get_password'], username).hashed_password
            if bcrypt.checkpw(bytes(password, encoding='utf-8'), result):
                session['user'] = username
                return redirect(url_for('index'))  # TODO: Генерировать тут сессию
            else:
                message = 'Wrong password.'
    return render_template('login.html', message=message)


@app.route('/registration', methods=['post', 'get'])
def registration():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        rep_password = str(request.form.get('rep_password'))
        if not username and password and rep_password:
            message = 'Empty login or one of passwords.'
        elif accessing_the_database(QUERY_COMMANDS['check_username'], username) is not None:  # count(username)
            message = 'User with the same name already exist.'
        elif not all(verify_password_on_correct(
                username=username, password=password,
                rep_password=rep_password).values()):
            message = PASSWORD_FORM
        elif rep_password != password:
            message = 'Passwords are not equal.'
        else:
            accessing_the_database(QUERY_COMMANDS['add_user'], username, bcrypt.hashpw(bytes(password, encoding='utf-8'), bcrypt.gensalt()).decode('utf-8'), changes=True)
            session['user'] = username
            return redirect(url_for('index'))  # TODO: Генерировать тут сессию
    return render_template('registration.html', message=message)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

@app.errorhandler(403)
def have_no_permission(e):
    return render_template('403.html')


@app.route('/about-us')
def about_us():
    return render_template('about-us.html')


@app.route('/videos')
def videos():
    return render_template('videos.html', listOfVideos={
        'Приaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'index', 'Еще видосик какой-то': 'login', '3': 'registration',
        '4': 'login', '5': 'login', '6': 'login',
        '7': 'login', '8': 'login', '9': 'login'})


@app.route('/profile')
def profile():
    if not 'user' in session:
        abort(403)
    return render_template('profile.html')


@app.route('/logout')
def logout():
    session.pop("user", None)
    return redirect(url_for('index'))


@app.route('/admin')
def admin():
    if not 'user' in session or \
            not accessing_the_database(QUERY_COMMANDS['get_user_role'], session['user']).role_type == 'admin':
        abort(403)
    return render_template('admin.html')


@app.route('/news')
def news():
    return render_template('news.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)