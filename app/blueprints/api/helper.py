from app import app, mail
from flask import jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity, create_access_token
from datetime import datetime, timezone, timedelta
from email_validator import validate_email, EmailNotValidError
from python_usernames import is_safe_username
from flask_mail import Message
import re



@app.after_request
def refresh_expiring_jwt(response):
    try:
        expiration = get_jwt()['exp']
        future_expire = datetime.timestamp(datetime.now(timezone.utc) + timedelta(minutes=30))
        if future_expire > expiration:
            access_token = create_access_token(identity= get_jwt_identity())
            data = response.get_json()
            data['access_token'] = access_token
            response = jsonify(data)
        return response  
    except (RuntimeError, KeyError):
        return response


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password reset Request', recipients=[user.email])
    msg.body =f'''To reset your password, use the following reset token within 15 minutes:

{token}


If you did not make this request, simply ignore this email and no changes will be made to your account.
'''
    mail.send(msg)


def nonvalid_email(email):
    try:
        emailinfo= validate_email(email, check_deliverability=True)
        email = emailinfo.normalized
        return False
    except EmailNotValidError as e:
        return True



def nonvalid_username(username):
    username = username.lower()
    if not is_safe_username(username, max_length=25):
        return True
    with open("./app/assets/bannedwords.txt" ,"r") as words:
        for w in words:
            word = w.strip()
            if re.search(f"{word.strip()}", username):
                return True
    return False



def nonvalid_password(password):
    pass_pattern = re.compile("^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[^\w\d\s:])([^\s]){8,500}$")
    if re.search(pass_pattern, password):
        return False
    return True



def update_character(id, changes):
    pass