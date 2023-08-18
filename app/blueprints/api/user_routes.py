from . import bp as api
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from app.models import  User, Character
from app.blueprints.api.helper import update_character


@api.post('/create-character')
@jwt_required()
def create_character():
    content = request.json
    if content:
        character = content['character']
        user = User.query.filter(User.uuid == get_jwt_identity()).first()
        try:
            char = create_character(character)
            char.commit()
        except:
            return jsonify({'error': 'invalid character info'}), 401
        return jsonify({'message': 'Character successfully created',
                        'loged in as' : user.username}), 200
    else:
        return jsonify({"data error": "Request must contain an keys for 'email', 'username' and 'password'."}),400



@api.get('/user/<username>')
@jwt_required()
def get_user_page(username):
    user = User.query.filter(User.username == username).first()
    if user:
        characters = user.characters
        return jsonify({
            'message': 'Success',
            'username': username,
            'characters' : [{character.uuid: character} for character in characters]
        }),200
    return jsonify({'error' : 'Not a valid username'}),401


@api.delete('/delete-character')
@jwt_required()
def delete_character():
    content = request.json
    if content:
        character_uuid = content['character_uuid']
        character = Character.query.get(id=character_uuid)
        if not character:
            return jsonify(message = 'Invalid Character Id'),401
        if character.maker.uuid != get_jwt_identity():
            return jsonify(message = 'You are not allowed to delete this character'),401
        character.delete()
        return jsonify(message = 'Character deleted'),200
    else:
        return jsonify({"data error": "Request must contain an key for 'character_uuid'."}),400



@api.post('/edit-character')
@jwt_required()
def edit_character():
    content = request.json
    if content:
        character_id = content['character_id']
        character_changes = content('character')
        character = Character.query.get(id=character_id)
        if not character:
            return jsonify(message = 'Invalid Character Id'),401
        if character.maker.uuid != get_jwt_identity():
            return jsonify(message = 'You are not allowed to edit this character'),401
        update_character(character_id, character_changes)
        character.update()
        return jsonify(message = 'Character edited'),200
    else:
        return jsonify({"data error": "Request must contain an key for 'character_id' and 'character' which contains the change data."}),400
