from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from ConfigMod import Config

app = Flask(__name__)

app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

CORS(app)
jwt = JWTManager(app)

mail = Mail(app)

from app.blueprints.api import bp as api
app.register_blueprint(api)


from app import  models

if __name__ == "__main__":
    # Run the Flask app on port 8000
    app.run(port=8000)
