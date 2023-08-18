from . import bp as api
from app.models import User
from app.blueprints.api.helper import nonvalid_email, nonvalid_username, nonvalid_password, send_reset_email

from flask import request, jsonify
from flask_jwt_extended import create_access_token, unset_jwt_cookies, jwt_required, decode_token


@api.post('/validate-access')
def valid_access_token():
    content = request.json
    if content:
        try:
            decode_token(content['access_token'])
            return jsonify({'success': 'Access token was verified' }),200
        except:
            return jsonify({'invalid': 'Invalid or expired token' }),400
    return jsonify({'bad data': 'access_token key is not avalible' }),400


@api.post('/login')
def login():
    content = request.json
    if content and 'email' in content and 'password' in content:
        email, password = content['email'], content['password']
        user = User.query.filter(User.email == email).first()
        if user and user.check_password(password):
            return jsonify({'username': user.username,
                'access_token': create_access_token(identity=user.uuid)}), 200
        else:
            return jsonify({'error': 'Invalid email or password. Try again.'}), 400
    return jsonify({"data error": "Request must contain an keys for 'email', 'username' and 'password'."}),400


@api.post('/sign-up')
def sign_up():
    content, response = request.json, {}
    if content and 'email' in content and 'username' in content and 'password' in content:
        if nonvalid_email(content['email']):
            response['email'] = f'Email is Invalid, only valid emails will be accepted.'
        elif User.query.filter(User.email == content['email']).first():
            response['email'] = f'Email is already exist in our system.'
        if nonvalid_username(content['username']):
            response['username'] = f'Username is Invalid, only valid username will be accepted. No fowl or offensive language will be accepted.'
        elif User.query.filter(User.username == content['username']).first():
            response['username'] = f'Username is already taken.'
        if nonvalid_password(content['password']):
            response['password'] = f'Password is Invalid. Valid password will be 8+ characters long and contain one of each, a capital letter, a lowercase letter, a number, and a special character.'
        if 'username' in response or 'password' in response or 'email' in response:
            return jsonify(response),400
        user = User()
        user.from_dict(content)
        try:
            user.hash_password(user.password)
            user.commit()
            return jsonify({'username': user.username,
                            'access_token': create_access_token(user.uuid)}),200
        except:
            return jsonify(response),400
    return jsonify({"error": "Request must contain an keys for 'email', 'username' and 'password'."}),400





@api.delete('/delete-user')
@jwt_required()
def delete_user():
    content = request.json
    if content and 'email' in content and 'username' in content and 'password' in content:
        password = content['password']
        username = content['username']
        email = content['email']
        user = User.query.filter(User.username == username).first()
        if user.email == email and user.check_password(password):
            for character in user.characters:
                character.delete()
            user.delete()
            return jsonify({'success' : f'Username: {user.username} account deleted.'}),200
        return jsonify({'error' : 'Invalid email, username or password.'}),400
    return jsonify({"error": "Request must contain an keys for 'email', 'username' and 'password'."}),400


@api.post('/logout')
def logout():
    response = jsonify({ 'success' : 'Successfully logged out.'})
    unset_jwt_cookies(response)
    return response



@api.post('/reset-request')
def reset_request():
    content = request.json
    if content and 'email' in content:
        if  User.query.filter(User.email == content['email']).first():
            user = User.query.filter(User.email == content['email']).first()
            send_reset_email(user)
            return jsonify({'success' : f'A reset email was sent to the email address on file for user with username {user.username}.'}),200
        return jsonify({'email' : 'Email is not in our system.'}),400
    return jsonify({"error": "Request must contain an keys for 'email'."}),400

@api.post('/reset-validate')
def validate_reset_token():
    content = request.json
    if content and 'reset_token' in content:
        user = User.verify_reset_token(content['reset_token'])
        if user:
            return jsonify({'success' : f'Token is valid'}),200
        return jsonify({'validation error' : 'Your token is either invalid or expired.'}),400
    return jsonify({"data error": "Request must contain an keys for 'reset_token' or 'password'."}),400

@api.post('/reset-password')
def reset_password():
    content = request.json
    if content and 'password' in content and 'reset_token' in content:
        user = User.verify_reset_token(content['reset_token'])
        if nonvalid_password(content['password']):
            return jsonify({'password' : 'New password is Invalid. Valid password must be 8+ characters long containing a capital letter, a lowercase letter, a number, and a special character..'}),400
        if user:
            user.hash_password(content['password'])
            return jsonify({'success' : f'The password has been updated for account {user.username}.'}),200
        return jsonify({'token' : 'Your token is either invalid or expired.'}),400
    return jsonify({"data error": "Request must contain an keys for 'reset_token' or 'password'."}),400
