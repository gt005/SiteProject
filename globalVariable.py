""" Файл для хранения глобальных переменных файла main.py """

QUERY_COMMANDS = {
    'get_user': "select * from users where username=%s;",
    'get_several_users': "select * from users where username like %s and username != %s;",
    'delete_user': "delete from users where username=%s;",
    'add_view_to_user': "update users set my_views = CONCAT(my_views, %s);",
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
    'add_one_view': "update files set views = views + 1 where id = %s;",
    'add_one_like': "update files set likes = likes + 1 where id = %s;",
    'remove_like': "update files set likes = likes - 1 where id = %s;",
    'create_file': "insert into files (username, file_name, category, file_path) values (%s, %s, %s, %s);",
    'search_files': "select * from files where file_name like %s;",
    'create_news': "insert into news (header, news_text, publication_time) values (%s, %s, %s);",
    'get_articles': "select * from news limit 20;",
    'set_auto_increment_null': "ALTER TABLE files AUTO_INCREMENT=0;"
}  # TODO: Дописать все команды

'''SELECT 
u1.* 
FROM 
users u1, 
random_seed rs
WHERE 
u1.role_id=5 AND u1.id=(rs.id+random_from_php)
ORDER BY 
rs.random_seed
LIMIT 10'''

PASSWORD_FORM = '''Password form: 
1) Use only latin character, numbers and symbol '_' 
2) Max length - 15
3) Min length - 3'''

SECRET_KEY = "BsKdQOcKBGAiScVZHkWovfitWBDEwIwi"

ALLOWED_IMAGE_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

ALLOWED_VIDEO_EXTENSIONS = set(['mp4', 'mov', 'avi', 'wmv', 'asf', 'webm', 'm4v'])

UPLOAD_FOLDER_FOR_PROFILE_IMAGE = '/Users/karimhamid/PycharmProjects/SiteProject/flask_app/static/images/profile_photos/'
UPLOAD_FOLDER_FOR_VIDEOS = '/Users/karimhamid/PycharmProjects/SiteProject/flask_app/static/videos/'