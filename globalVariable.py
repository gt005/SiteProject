""" Файл для хранения глобальных переменных файла main.py """

QUERY_COMMANDS = {
    'get_user': "select * from users where username=%s;",
    'get_several_users': "select * from users where username like %s and username != %s;",
    'delete_user': "delete from users where username=%s;",
    'change_to_admin': "update users set role_type='admin' where username=%s;",
    'add_user': "insert into users (username, hashed_password) values (%s, %s);",
    'get_all_files': "select * from files;",
    'get_file_with_category': "select * from files where category=%s;",
    'create_news': "insert into news (header, news_text, publication_time) values (%s, %s, %s);",
    'get_articles': "select * from news limit 15;"
}  # TODO: Дописать все команды

PASSWORD_FORM = '''Password form: 
1) Use only latin character, numbers and symbol '_' 
2) Max length - 15
3) Min length - 3'''

SECRET_KEY = "BsKdQOcKBGAiScVZHkWovfitWBDEwIwi"

ALLOWED_IMAGE_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

ALLOWED_VIDEO_EXTENSIONS = set(['mp4'])

UPLOAD_FOLDER_FOR_PROFILE_IMAGE = '/Users/karimhamid/PycharmProjects/SiteProject/flask_app/static/images/profile_photos/'