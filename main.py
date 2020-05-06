import os
import re
from flask import Flask, request, g, abort, render_template, url_for, redirect, make_response, session
from app import app
import bcrypt
import mysql.connector
from werkzeug.utils import secure_filename
from globalVariable import *
import hashlib


data_base = mysql.connector.connect(
    # Конфигурация моей базы данных, у тебя не будет работать, надо менять
    host='localhost',
    user='root',
    passwd='gt005gt005',
    database='sitedb'
)

db_cursor = data_base.cursor()


class User():
    ''' Структура, которая содержет в себе свойства, например имя пользователя '''
    def __init__(self, *args):
        self.username = args[0]
        self.hashed_password = args[1]
        self.rating_sport = args[2]
        self.rating_creation = args[3]
        self.rating_study = args[4]
        self.role_type = args[5]


class File():
    pass


def upload_file(file, upload_folder):
    if not file:
        return 'Choose a file.'
    if not allowed_file(file.filename):
        return 'Invalid file name.'
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(upload_folder, hashlib.md5(bytes(session['user'], encoding='utf-8')).hexdigest() + '.png'))
        return 'Success'


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def verify_password_on_correct(**verifiable):
    """ Проверяет, нет ли в строке лишних символов.
        dict([str key: str element],) -> dict([str key: bool],)
        В конце возвращает словарь, где каждому ключу соответвует занчение,
        подходит ли строка или нет.
    """
    result = dict()
    expression = re.compile(r'[a-zA-Z0-9_]{5,15}$')  # Сверяет разрешенные символы и длину
    for key, element in verifiable.items():
        if expression.match(element):  # Проходит проверку или нет
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
        query = query % args  # Вставляет в запрос переменные
        db_answer = function(query=query, changes=changes)
        if not changes and db_answer:
            if len(db_answer) == 1:
                return type_of_object(*(db_answer[0]))  # Формат ответа [(username, hashed_password......)]
            else:
                return [type_of_object(*(db_answer[i])) for i in db_answer]
    return wrapper  # Возвращает значение wrapper


@queryToObject  # Вызывая эту функцию(accessing_the_database), будет выполняться queryToObject
def accessing_the_database(query, changes=False):
    db_cursor.execute(query)  # Выполняет запрос
    if changes:
        data_base.commit()  # Подтверждает изменения в базе данных
        return None
    return db_cursor.fetchall()  # Достает то, что вернул запрос


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
        username = str(request.form.get('username'))   # Достает значения из формы по методу POST
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
                return redirect(url_for('index'))
            else:
                message = 'Wrong password.'
    return render_template('login.html', message=message)


@app.route('/registration', methods=['post', 'get'])
def registration():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        username = str(request.form.get('username'))  # Достает значения из формы по методу POST
        password = str(request.form.get('password'))
        rep_password = str(request.form.get('rep_password'))
        if not username and password and rep_password:
            message = 'Empty login or one of passwords.'
        elif accessing_the_database(QUERY_COMMANDS['check_username'], username) is not None:  # None, если нет таких пользователей
            message = 'User with the same name already exist.'
        elif not all(verify_password_on_correct(
                username=username, password=password,
                rep_password=rep_password).values()):
            # Если хоть один не проходит проверку функцией verify_password_on_correct
            message = PASSWORD_FORM
        elif rep_password != password:
            message = 'Passwords are not equal.'
        else:
            accessing_the_database(QUERY_COMMANDS['add_user'], username, bcrypt.hashpw(bytes(password, encoding='utf-8'), bcrypt.gensalt()).decode('utf-8'), changes=True)
            session['user'] = username  # Ставит cookie сессии
            return redirect(url_for('index'))
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
    # Вместо этого словаря будет из базы данных брать данные
    return render_template('videos.html', listOfVideos={
        'Приaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'index', 'Еще видосик какой-то': 'login', '3': 'registration',
        '4': 'login', '5': 'login', '6': 'login',
        '7': 'login', '8': 'login', '9': 'login'})


@app.route('/videos/category/<category>')  # Вместо <> подставится значение, оно же передастся в функцию
def watch_category(category):
    return render_template('videos.html', listOfVideos={
        'Приaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'index',
        'Еще видосик какой-то': 'login', '3': 'registration',
        '4': 'login', '5': 'login', '6': 'login',
        '7': 'login', '8': 'login', '9': 'login'})


@app.route('/profile', methods=['post', 'get'])
def profile():
    file_path = os.path.join(UPLOAD_FOLDER_FOR_PROFILE_IMAGE, hashlib.md5(  # Путь к аватарке
        bytes(session['user'], encoding='utf-8')).hexdigest() + '.png')
    if not os.path.exists(file_path):   #  Если аватарки нет, то выводить стандартную
        file_name = 'standard_image.png'
    else:
        file_name =  hashlib.md5(bytes(session['user'], encoding='utf-8')).hexdigest() + '.png'
    message = ''
    print(request.method)
    if request.method == 'POST':
        if request.files:
            file = request.files['file']
            message = upload_file(file, UPLOAD_FOLDER_FOR_PROFILE_IMAGE)
    if not 'user' in session:
        # Если не user залогинен, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    return render_template('profile.html', message=message, file_name=file_name)


@app.route('/logout')
def logout():
    session.pop("user", None)    # Удаляет cookie сессии
    return redirect(url_for('index'))


@app.route('/admin', methods=['post', 'get'])
def admin():
    if not 'user' in session or \
            not accessing_the_database(QUERY_COMMANDS['get_user_role'], session['user']).role_type == 'admin':
        # Проверяет, является ли человек админом, если нет, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    if request.method == 'POST':
        news_header = str(request.form.get('news_header'))
        news_text = str(request.form.get('news_text'))


    return render_template('admin.html')


@app.route('/news')
def news():
    return render_template('news.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)