from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api
from flask_marshmallow import Marshmallow

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, instance_relative_config=False)

    # Application Configuration
    app.config.from_object('config.Config')

    # Initialize the app with the extension
    db.init_app(app)

    # Init marshmallow
    global ma
    ma = Marshmallow(app)

    with app.app_context():
        from .views import (Registration, Auth, User, Group,
                            GroupUser, UserFilter, Chat)

        # Create Database Models
        db.create_all()

        # Init api
        api = Api(app)

        # App Routes
        api.add_resource(Registration, '/api/v1.0/register')
        api.add_resource(Auth, '/api/v1.0/auth')
        api.add_resource(User, '/api/v1.0/user')
        api.add_resource(Group, '/api/v1.0/group')
        api.add_resource(GroupUser, '/api/v1.0/group_user')
        api.add_resource(Chat, '/api/v1.0/chat')
        api.add_resource(UserFilter, '/api/v1.0/filter')
        return app
