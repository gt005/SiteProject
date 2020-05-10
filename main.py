import os
import re
import hashlib
import datetime
from random import randint
from flask import Flask, request, g, abort, render_template, url_for, redirect, make_response, session
import bcrypt
import mysql.connector
from werkzeug.utils import secure_filename
from globalVariable import *


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = datetime.timedelta(days=7)


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
        self.my_likes = args[6]
        self.my_views = args[7]


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


def upload_file(file, upload_folder, file_type, *args, last_id=None, file_object=None):
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


def allowed_file(filename, file_type, *args):
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


def queryToObject(function, *args):
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
            # Формат ответа [(username, hashed_password......),]
            return [type_of_object(*(db_answer[i])) for i in range(len(db_answer))]
        if not db_answer:
            return []
    return wrapper  # Возвращает значение отработавшего wrapper (немного не так, но для понимания)


def findVideo(*args):
    if request.method == 'POST' and request.form.get('commit_search'):
        search_string = str(request.form.get('search_string'))
        return search_string.lower()


@queryToObject  # Вызывая эту функцию(accessing_the_database), будет выполняться queryToObject
def accessing_the_database(query, args, *other, changes=False):
    db_cursor.execute(query, args)  # Выполняет запрос
    if changes:
        data_base.commit()  # Подтверждает изменения в базе данных
        return None
    return db_cursor.fetchall()  # Достает то, что вернул запрос


@app.route('/', methods=['post', 'get'])
def news():
    search = findVideo()
    if search: return redirect(url_for('videos', category='search', search_string=search))
    articles = accessing_the_database(QUERY_COMMANDS['get_articles'])
    return render_template('news.html', article_list=articles[::-1])


@app.route('/login', methods=['post', 'get'])
def login():
    if 'user' in session:
        abort(403)
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST' and request.form.get('do_signin'):
        session.permanent = True
        username = str(request.form.get('username'))   # Достает значения из формы по методу POST
        password = str(request.form.get('password'))
        if not username and password:
            message = 'Empty login or password.'
        elif not accessing_the_database(QUERY_COMMANDS['get_user'], username):  # count(username)
            message = 'User does not exist.'
        elif not all(verify_password_on_correct(username=username, password=password).values()):
            message = PASSWORD_FORM
        else:
            result = accessing_the_database(QUERY_COMMANDS['get_user'], username)[0]
            if bcrypt.checkpw(bytes(password, encoding='utf-8'), result.hashed_password):
                session['user'] = username
                session['role'] = result.role_type
                return redirect(url_for('news'))
            else:
                message = 'Wrong password.'
    return render_template('login.html', message=message)


@app.route('/registration', methods=['post', 'get'])
def registration():
    if 'user' in session:
        abort(403)
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    message = ''  # Для вывода предупреждений в форме
    if request.method == 'POST':
        username = str(request.form.get('username'))  # Достает значения из формы по методу POST
        password = str(request.form.get('password'))
        rep_password = str(request.form.get('rep_password'))
        if not username and password and rep_password:
            message = 'Empty login or one of passwords.'
        elif accessing_the_database(QUERY_COMMANDS['get_user'], username):  # None, если нет таких пользователей
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
            session['role'] = 'member'
            return redirect(url_for('news'))
    return render_template('registration.html', message=message)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')


@app.errorhandler(403)
def have_no_permission(e):
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    return render_template('403.html')


@app.route('/scoreboard', methods=['post', 'get'])
def scoreboard():
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    user_in_scoreboard_sport = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_sport')
    user_in_scoreboard_creation = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_creation')
    user_in_scoreboard_study = accessing_the_database(QUERY_COMMANDS['get_scoreboard'], 'rating_study')
    # Меняет значения None на 0
    for i in range(len(user_in_scoreboard_sport)):
        if user_in_scoreboard_sport[i].rating_sport is None:
            user_in_scoreboard_sport[i].rating_sport = 0
    for i in range(len(user_in_scoreboard_creation)):
        if user_in_scoreboard_creation[i].rating_creation is None:
            user_in_scoreboard_creation[i].rating_creation = 0
    for i in range(len(user_in_scoreboard_study)):
        if user_in_scoreboard_study[i].rating_study is None:
            user_in_scoreboard_study[i].rating_study = 0

    return render_template('scoreboard.html',
                           user_in_scoreboard_sport=sorted(user_in_scoreboard_sport, key=lambda x: (-x.rating_sport, x.username)),
                           user_in_scoreboard_creation=sorted(user_in_scoreboard_creation, key=lambda x: (-x.rating_creation, x.username)),
                           user_in_scoreboard_study=sorted(user_in_scoreboard_study, key=lambda x: (-x.rating_study, x.username)))


@app.route('/videos/<category>', methods=['post', 'get'])
def videos(category):
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    if request.args.get('p') is not None and request.args.get('p').isdigit():
        page = int(request.args.get('p')) - 1
    elif request.args.get('p') is None:
        page = 0
    else:
        abort(404)

    if category == 'All categories':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_all_files'])
    elif category == 'Sport':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Sport')
    elif category == 'Creation':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Creation')
    elif category == 'Study':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_file_with_category'], 'Study')
    elif category == 'Popular':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['get_popular_videos'])
    elif category == 'search':
        listOfVideos = accessing_the_database(QUERY_COMMANDS['search_files_or_users'], f"%{request.args.get('search_string')}%", f"%{request.args.get('search_string')}%")[:6]
        category = 'Search for: ' + request.args.get('search_string')
    else:
        abort(404)

    amount_of_pages = (len(listOfVideos) + 6 - 1) // 6
    listOfVideos = listOfVideos[page * 6: page * 6 + 6]

    if listOfVideos is None:
        listOfVideos = ''
    return render_template('videos.html', category=category, amount_of_pages=amount_of_pages, page='page - ' + str(page + 1), listOfVideos=listOfVideos)


@app.route('/profile', methods=['post', 'get'])
def profile():
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    if not 'user' in session:
        # Если не user залогинен, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    if request.args.get('command') == 'delete_file':
        if request.args.get('video_file_id'):
            video_file = request.args.get('video_file_id')
            video_file_object = accessing_the_database(QUERY_COMMANDS['get_file'], video_file)[0]
            if video_file_object.username != session['user']:
                abort(403)
                return ''
            os.remove(UPLOAD_FOLDER_FOR_VIDEOS + video_file_object.file_path[video_file_object.file_path.rfind('/'):])  # отрезаем только название
            accessing_the_database(QUERY_COMMANDS['delete_file'], video_file_object.id, changes=True)
            accessing_the_database(QUERY_COMMANDS[f'recalculate_{video_file_object.category.lower()}_rating'], *([video_file_object.username, video_file_object.category] * 3), video_file_object.username, changes=True)  # Нужно 4 раза передать сессию
            return redirect(url_for('profile'))
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

    listOfMyVideosForProfile = accessing_the_database(QUERY_COMMANDS['get_user_files'], session['user'])
    return render_template('profile.html', message=message, file_name=file_name, listOfMyVideosForProfile=listOfMyVideosForProfile)


@app.route('/logout', methods=['post', 'get'])
def logout():
    session.pop("user", None)    # Удаляет cookie сессии
    session.pop("role", None)
    return redirect(url_for('news'))


@app.route('/admin', methods=['post', 'get'])
def admin(command=None, user=None):
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    if not 'user' in session or \
            not accessing_the_database(QUERY_COMMANDS['get_user'], session['user'])[0].role_type == 'admin':
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
                publication_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
                if not user:
                    message_to_the_users_search = 'Users not found'
    elif request.args.get('command') == 'delete' and request.args['user']:
        for video_file_object in accessing_the_database(QUERY_COMMANDS['get_user_files'], request.args['user']):
            os.remove(UPLOAD_FOLDER_FOR_VIDEOS + video_file_object.file_path[video_file_object.file_path.rfind('/'):])  # отрезаем только название
            accessing_the_database(QUERY_COMMANDS['delete_file'],
                                   video_file_object.id, changes=True)
        if os.path.exists(os.path.join(UPLOAD_FOLDER_FOR_PROFILE_IMAGE, hashlib.md5(bytes(request.args['user'], encoding='utf-8')).hexdigest() + '.png')):
            os.remove(os.path.join(UPLOAD_FOLDER_FOR_PROFILE_IMAGE, hashlib.md5(bytes(request.args['user'], encoding='utf-8')).hexdigest() + '.png'))
        accessing_the_database(QUERY_COMMANDS['delete_user'], request.args['user'], changes=True)
        message_to_the_users_search = 'Successfully deleted'
        return redirect(url_for('admin'))
    elif request.args.get('command') == 'change_role' and request.args['user']:
        accessing_the_database(QUERY_COMMANDS['change_to_admin'], request.args['user'], changes=True)
        return redirect(url_for('admin'))

    return render_template('admin.html', message=message, message_to_the_users_search=message_to_the_users_search, user=user)


@app.route('/video_player', methods=['post', 'get'])
def video_player():
    if 'user' in session:
        current_user = accessing_the_database(QUERY_COMMANDS['get_user'], session['user'])[0]
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    if request.args.get('video_file') is None or not request.args.get('video_file').isdigit():
        abort(404)
    video_file = accessing_the_database(QUERY_COMMANDS['get_file'],
                                        int(request.args.get('video_file')))
    if not video_file:
        abort(404)
    else:
        video_file = video_file[0]
    if 'user' in session and request.args.get('like_button_pressed') == 'True':
        if f"?{int(request.args.get('video_file'))}?" not in current_user.my_likes and video_file.username != session['user']:
            accessing_the_database(QUERY_COMMANDS['add_one_like'], int(request.args.get('video_file')), changes=True)
            accessing_the_database(QUERY_COMMANDS['add_likes_to_user'], f"{int(request.args.get('video_file'))}?", session['user'], changes=True)
            accessing_the_database(QUERY_COMMANDS[f'recalculate_{video_file.category.lower()}_rating'], *([video_file.username, video_file.category] * 3), video_file.username, changes=True)  # Нужно 4 раза передать сессию
            return redirect(url_for('video_player', video_file=int(request.args.get('video_file'))))
    elif (request.args.get('command') == 'delete_file') and ('role' in session) and session['role'] == 'admin':
        accessing_the_database(QUERY_COMMANDS['delete_file'], video_file.id, changes=True)
        os.remove(UPLOAD_FOLDER_FOR_VIDEOS + video_file.file_path[
                                             video_file.file_path.rfind(
                                                 '/'):])
        return redirect(url_for('videos', category='All categories'))

    else:
        if not video_file:  # Если пользователь все-таки не вставил свой id в строку поиска и такого видео нет
            abort(404)
        if 'user' in session and video_file.username != session['user']:
            if f"?{video_file.id}?" not in current_user.my_views: # Если видео не просмотрено(нет в просмотрах)
                accessing_the_database(QUERY_COMMANDS['add_one_view'], video_file.id, changes=True)
                accessing_the_database(QUERY_COMMANDS['add_view_to_user'], f"{video_file.id}?", session['user'], changes=True)
                accessing_the_database(QUERY_COMMANDS[f'recalculate_{video_file.category.lower()}_rating'], *([video_file.username, video_file.category] * 3), video_file.username, changes=True)  # Нужно 4 раза передать сессию
    if 'user' in session and (f"?{request.args.get('video_file')}?" in current_user.my_likes or video_file.username == session['user']):
        like_button = 'liked'
    else:
        like_button = 'not liked'

    listOfVideos = accessing_the_database(QUERY_COMMANDS['get_random_files'], video_file.id)
    return render_template('video_player.html', video_file=video_file, like_button=like_button, listOfVideos=listOfVideos)


@app.route('/add_video', methods=['post', 'get'])
def add_new_video():
    if not 'user' in session:
        # Если не user залогинен, вызывает ошибку 403 и переходит на ф-ию have_no_permission
        abort(403)
    search = findVideo()
    if search: return redirect(
        url_for('videos', category='search', search_string=search))
    message = ''
    if request.method == 'POST' and session['user']:
        video_name = request.form.get('video_name')
        if request.files['video_file']:
            if video_name:
                file = request.files['video_file']
                category = request.form.get('category')
                last_id = accessing_the_database(QUERY_COMMANDS['get_last_file_id'])  # смотрим последний id, чтобы добавить по имени md5(id + 1), что позволит создать уникальные названия
                if not last_id:
                    accessing_the_database(QUERY_COMMANDS['set_auto_increment_null'], changes=True)
                    last_id = 0
                else:
                    last_id = last_id[0].id
                new_video_file = File(last_id + 1, session['user'], video_name, category, 0, 0, os.path.join('../static/videos/',
                                             hashlib.md5(bytes(str(last_id + 1), encoding='utf-8')).hexdigest() \
                                             + file.filename[file.filename.rfind('.'):]))
                message = upload_file(file, UPLOAD_FOLDER_FOR_VIDEOS, 'video', new_video_file, last_id=last_id)
                if message == 'Success':
                    accessing_the_database(QUERY_COMMANDS['create_file'], session['user'], video_name, category, new_video_file.file_path, changes=True)
            else:
                message = 'Empty video name'
        else:
            message = 'Load a file'

    return render_template('add_new_video.html', message=message)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)