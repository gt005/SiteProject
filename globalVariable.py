""" Файл для хранения глобальных переменных файла main.py """


QUERY_COMMANDS = {
    'check_username': "select count(username) from users where username='%s';",
    'add_user': "insert into users (username, hashed_password) values ('%s', '%s');",
    'get_password': "select hashed_password from users where username='%s';"
}  # TODO: Дописать все команды


PASSWORD_FORM = '''Password form: 
1) Use only latin character, numbers and symbol '_' 
2) Max length - 15
3) Min length - 5'''

SECRET_KEY = "BsKdQOcKBGAiScVZHkWovfitWBDEwIwi"