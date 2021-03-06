""" Файл для хранения глобальных переменных файла main.py """
import re


QUERY_COMMANDS = {
    'get_user': "select * from users where username=%s;",
    'get_several_users': "select * from users where username like %s and username != %s;",
    'delete_user': "delete from users where username=%s;",
    'add_view_to_user': "update users set my_views = CONCAT(my_views, %s) where username=%s;",
    'add_likes_to_user': "update users set my_likes = CONCAT(my_likes, %s) where username=%s;",
    'get_scoreboard': "select * from users order by %s desc limit 50;",
    'change_to_admin': "update users set role_type='admin' where username=%s;",
    'add_user': "insert into users (username, hashed_password) values (%s, %s);",
    'get_all_files': "select * from files order by category;",
    'get_last_file_id': "select * from files order by id desc limit 1;",
    'get_popular_videos': "select * from files order by views desc;",
    'get_file_with_category': "select * from files where category=%s;",
    'get_user_files': "select * from files where username=%s;",
    'delete_file': "delete from files where id=%s;",
    'get_file': "select * from files where id=%s;",
    'get_random_files': "select * from files where id != %s order by rand() limit 6;",
    'add_one_view': "update files set views = views + 1 where id = %s;",
    'add_one_like': "update files set likes = likes + 1 where id = %s;",
    'remove_like': "update files set likes = likes - 1 where id = %s;",
    'create_file': "insert into files (username, file_name, category, file_path) values (%s, %s, %s, %s);",
    'search_files_or_users': "select * from files where file_name like %s or username like %s;",
    'create_news': "insert into news (header, news_text, publication_time) values (%s, %s, %s);",
    'get_articles': "select * from news limit 20;",
    'delete_article': "delete from news where id=%s;",
    'set_auto_increment': "ALTER TABLE files AUTO_INCREMENT=%s;",
    'recalculate_sport_rating': "update users set rating_sport = ((select sum(likes) from files where username=%s and category=%s) / (select sum(views) from files where username=%s and category=%s) / (select count(*) from files where username=%s and category=%s) * 1000 DIV 1) where username=%s;",
    'recalculate_creation_rating': "update users set rating_creation = ((select sum(likes) from files where username=%s and category=%s) / (select sum(views) from files where username=%s and category=%s) / (select count(*) from files where username=%s and category=%s) * 1000 DIV 1) where username=%s;",
    'recalculate_study_rating': "update users set rating_study = ((select sum(likes) from files where username=%s and category=%s) / (select sum(views) from files where username=%s and category=%s) / (select count(*) from files where username=%s and category=%s) * 1000 DIV 1) where username=%s;",
    'get_auto_increment': "SELECT AUTO_INCREMENT FROM information_schema.tables WHERE table_name = %s and table_schema = 'sitedb';",
    'set_like_to_user': "update users set my_likes=%s where username=%s;"
}

SECRET_KEY = "BsKdQOcKBGAiScVZHkWovfitWBDEwIwi"

ALLOWED_IMAGE_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

ALLOWED_VIDEO_EXTENSIONS = set(['mp4', 'mov', 'avi', 'wmv', 'asf', 'webm', 'm4v'])

UPLOAD_FOLDER_FOR_PROFILE_IMAGE = '/home/gt005/mysite/SiteProject/static/images/profile_photos/'
UPLOAD_FOLDER_FOR_VIDEOS = '/Users/karimhamid/PycharmProjects/SiteProject/flask_app/static/videos/'

MAX_PHOTO_FILE_SIZE = 1024 * 1024 * 2 + 1
MAX_VIDEO_FILE_SIZE = 1024 * 1024 * 10 + 1

NEW_PASSWORD_EXPRESSION = re.compile(r"(?=^.{6,20}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?![.\s])(?=.*[A-Z])(?=.*[a-z]).*$")

DEVELOPMENT_MODE = True