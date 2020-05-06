""" Файл для хранения глобальных переменных файла main.py """

QUERY_COMMANDS = {
    'check_username': "select * from users where username='%s';",
    'add_user': "insert into users (username, hashed_password) values ('%s', '%s');",
    'get_password': "select * from users where username='%s';",
    'get_user_role': "select * from users where username='%s';",
    'get_all_files': "select * from files;",
    'get_file_with_category': "select * from files where category='%s';"
}  # TODO: Дописать все команды

PASSWORD_FORM = '''Password form: 
1) Use only latin character, numbers and symbol '_' 
2) Max length - 15
3) Min length - 5'''

SECRET_KEY = "BsKdQOcKBGAiScVZHkWovfitWBDEwIwi"