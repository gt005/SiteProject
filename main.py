import os
import re
import hashlib
import datetime
from flask import Flask, request, g, abort, render_template, url_for, redirect, make_response, session
from app import app
import bcrypt
import mysql.connector
from werkzeug.utils import secure_filename
from globalVariable import *


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
    def __init__(self, *args):
        self.id = args[0]
        self.username = args[1]
        self.file_name = args[2]
        self.category = args[3]
        self.views = args[4]
        self.likes = args[5]
        self.file_path = args[6]


class Article():
    def __init__(self, *args):
        self.id = args[0]
        self.header = args[1]
        self.text = args[2]
        self.publication_time = args[3]


def upload_file(file, upload_folder, file_type, last_id, file_object=None):
    if not file:
        return 'Choose a file.'
    if not allowed_file(file.filename, file_type):
        return 'Invalid file name.'
    if file and allowed_file(file.filename, file_type) and file_type == 'image':
        filename = secure_filename(file.filename)
        file.save(os.path.join(upload_folder, hashlib.md5(bytes(session['user'], encoding='utf-8')).hexdigest() + '.png'))
        return 'Success'
    elif file and allowed_file(file.filename, file_type) and file_type == 'video':
        file.save(os.path.join(upload_folder, hashlib.md5(
                         bytes(str(last_id + 1), encoding='utf-8')).hexdigest() \
                     + file.filename[file.filename.rfind('.'):]))
        return 'Success'


def allowed_file(filename, file_type):
    if file_type == 'image':
        extensions = ALLOWED_IMAGE_EXTENSIONS
    else:
        extensions = ALLOWED_VIDEO_EXTENSIONS
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in extensions


def verify_password_on_correct(**verifiable):
    """ Проверяет, нет ли в строке лишних символов.
        dict([str key: str element],) -> dict([str key: bool],)
        В конце возвращает словарь, где каждому ключу соответвует занчение,
        подходит ли строка или нет.
    """
    result = dict()
    expression = re.compile(r'[a-zA-Z0-9_]{3,15}$')  # Сверяет разрешенные символы и длину
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
        if 'from users' in query:
            type_of_object = User
        elif 'from files' in query:
            type_of_object = File
        elif 'from news' in query:
            type_of_object = Article
        db_answer = function(query=query, args=args, changes=changes)
        if not changes and db_answer:
            if len(db_answer) == 1:
                return type_of_object(*(db_answer[0]))  # Формат ответа [(username, hashed_password......)]
            else:
                return [type_of_object(*(db_answer[i])) for i in range(len(db_answer))]
    return wrapper  # Возвращает значение wrapper


@queryToObject  # Вызывая эту функцию(accessing_the_database), будет выполняться queryToObject
def accessing_the_database(query, args, changes=False):
    db_cursor.execute(query, args)  # Выполняет запрос
    if changes:
        data_base.commit()  # Подтверждает изменения в базе данных
        return None
    return db_cursor.fetchall()  # Достает то, что вернул запрос


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['post', 'get'])
def login():
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST' and request.form.get('do_signin'):
        session.permanent = True
        username = str(request.form.get('username'))   # Достает значения из формы по методу POST
        password = str(request.form.get('password'))
        if not username and password:
            message = 'Empty login or password.'
        elif accessing_the_database(QUERY_COMMANDS['get_user'], username) is None:  # count(username)
            message = 'User does not exist.'
        elif not all(verify_password_on_correct(username=username, password=password).values()):
            message = PASSWORD_FORM
        else:
            result = accessing_the_database(QUERY_COMMANDS['get_user'], username).hashed_password
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
        elif accessing_the_database(QUERY_COMMANDS['get_user'], username) is not None:  # None, если нет таких пользователей
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


@app.route('/scoreboard')
def scoreboard():
    user_in_scoreboard_sport = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_sport')
    user_in_scoreboard_creation = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_creation')
    user_in_scoreboard_study = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_study')
    if not isinstance(user_in_scoreboard_sport, list):
        user_in_scoreboard_study = [user_in_scoreboard_study]
        user_in_scoreboard_sport = [user_in_scoreboard_sport]
        user_in_scoreboard_creation = [user_in_scoreboard_creation]
    return render_template('scoreboard.html',
                           user_in_scoreboard_sport=sorted(user_in_scoreboard_sport, key=lambda x: (-x.rating_sport, x.username)),
                           user_in_scoreboard_creation=sorted(user_in_scoreboard_creation, key=lambda x: (-x.rating_creation, x.username)),
                           user_in_scoreboard_study=sorted(user_in_scoreboard_study, key=lambda x: (-x.rating_study, x.username)))


@app.route('/videos/<category>')
def videos(category):
    page = request.args.get('p')

    if page is None:
        page = 0
    elif page.isdigit():
        page = int(page) - 1
    else:
        abort(404)

    if category == 'All categories':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_all_files'])
    elif category == 'Sport':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Sport', page * 10, page * 10 + 20)
    elif category == 'Creation':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Creation', page * 10, page * 10 + 20)
    elif category == 'Study':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Study', page * 10, page * 10 + 20)
    elif category == 'Popular':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_popular_videos'], page * 10, page * 10 + 20)
    else:
        abort(404)
    if not isinstance(listOfVideos, list) and listOfVideos:
        listOfVideos = [listOfVideos]
    elif listOfVideos is None:
        listOfVideos = ''
    return render_template('videos.html', category=category,page='page - ' + str(page + 1), listOfVideos={video.id: video for video in listOfVideos})


@app.route('/profile', methods=['post', 'get'])
def profile():
    file_path = os.path.join(UPLOAD_FOLDER_FOR_PROFILE_IMAGE, hashlib.md5(  # Путь к аватарке
        bytes(session['user'], encoding='utf-8')).hexdigest() + '.png')
    if not os.path.exists(file_path):   #  Если аватарки нет, то выводить стандартную
        file_name = 'standard_image.png'
    else:
        file_name =  hashlib.md5(bytes(session['user'], encoding='utf-8')).hexdigest() + '.png'
    message = ''
    if request.method == 'POST':
        if request.files:
            file = request.files['file']
            message = upload_file(file, UPLOAD_FOLDER_FOR_PROFILE_IMAGE, 'image')
    if not 'user' in session:
        # Если не user залогинен, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    return render_template('profile.html', message=message, file_name=file_name, listOfVideos={
        'Приaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'index', 'Еще видосик какой-то': 'login', '3': 'registration',
        '4': 'login', '5': 'login', '6': 'login',
        '7': 'login', '8': 'login', '9': 'login'})


@app.route('/logout')
def logout():
    session.pop("user", None)    # Удаляет cookie сессии
    return redirect(url_for('index'))


@app.route('/admin', methods=['post', 'get'])
def admin(command=None, user=None):
    if not 'user' in session or \
            not accessing_the_database(QUERY_COMMANDS['get_user'], session['user']).role_type == 'admin':
        # Проверяет, является ли человек админом, если нет, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    message = ''
    user = ''
    message_to_the_users_search = ''
    if request.method == 'POST':
        if request.form.get('add-news'):
            news_header = str(request.form.get('news_header'))
            news_text = str(request.form.get('news_text'))
            if not (news_header and news_text):
                message = 'Empty header or text'
            else:
                publication_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                accessing_the_database(
                    QUERY_COMMANDS['create_news'], news_header,
                    news_text, publication_time, changes=True)
                message = 'Successfully created an article.'
        elif request.form.get('find-user'):
            user = request.form.get('search-username')
            if not user:
                message_to_the_users_search = 'Empty username'
            else:
                user = accessing_the_database(QUERY_COMMANDS['get_several_users'], user + '%', session['user'])
                if not isinstance(user, list) and user is not None:
                    user = [user]
                if user is None:
                    message_to_the_users_search = 'Users not found'
    elif request.args.get('command') == 'delete' and request.args['user']:
        accessing_the_database(QUERY_COMMANDS['delete_user'], request.args['user'], changes=True)
        message_to_the_users_search = 'Successfully deleted'
        return redirect(url_for('admin'))
    elif request.args.get('command') == 'change_role' and request.args['user']:
        accessing_the_database(QUERY_COMMANDS['change_to_admin'], request.args['user'], changes=True)
        return redirect(url_for('admin'))
    return render_template('admin.html', message=message, message_to_the_users_search=message_to_the_users_search, user=user)


@app.route('/news')
def news():
    articles = accessing_the_database(QUERY_COMMANDS['get_articles'])
    if not isinstance(articles, list):  # Если вернулся один элемент, делаем список, чтобы при for не было ошибок
        articles = [articles]
    return render_template('news.html', article_list=articles[::-1])


@app.route('/video_player')
def video_player():
    return render_template('video_player.html', video_name="Приключения кота и его подруги!")


@app.route('/add_video', methods=['post', 'get'])
def add_new_video():
    message = ''
    if request.method == 'POST' and session['user']:
        video_name = request.form.get('video_name')
        if request.files['video_file']:
            if video_name:
                file = request.files['video_file']
                category = request.form.get('category')
                last_id = accessing_the_database(QUERY_COMMANDS['get_last_file_id']).id  # смотрим последний id, чтобы добавить по имени md5(id + 1), что позволит создать уникальные названия
                new_video_file = File(last_id + 1, session['user'], video_name, category, 0, 0, os.path.join('../static/videos/',
                                             hashlib.md5(bytes(str(last_id + 1), encoding='utf-8')).hexdigest() \
                                             + file.filename[file.filename.rfind('.'):]))
                message = upload_file(file, UPLOAD_FOLDER_FOR_VIDEOS, 'video', last_id, new_video_file)
                if message == 'Success':
                    accessing_the_database(QUERY_COMMANDS['create_file'], session['user'], video_name, category, new_video_file.file_path, changes=True)
            else:
                message = 'Empty video name'
        else:
            message = 'Load a file'

    return render_template('add_new_video.html', message=message)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)