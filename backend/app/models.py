import jwt
import datetime
from os import environ

from sqlalchemy.sql import func
from passlib.apps import custom_app_context as pwd_context

from app import db


class UserModel(db.Model):
    """User account model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    icon = db.Column(db.String(60))
    username = db.Column(db.String(60), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    email = db.Column(db.String(60), unique=True)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    last_login = db.Column(db.DateTime(timezone=True), default=func.now())
    token = db.relationship('AuthTokensModel', backref='users', uselist=False)
    group = db.relationship('GroupUserModel', backref='users')

    def __repr__(self) -> str:
        return f'<User: {self.username}>'

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password, password_hash) -> bool:
        return pwd_context.verify(password, password_hash)

    def create(self):
        pass

    def update(self):
        pass

    def delete(self, user):
        db.session.delete(user)
        db.session.commit()

class AuthTokensModel(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(300), unique=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self) -> str:
        return f'<User_id: {self.userid}>'

    def get_auth_token(self, userid) -> str:
        """
        Generates the Auth Token
        """
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=3),
            'sub': userid
        }
        self.token = jwt.encode(payload, environ.get('SECRET_KEY'), algorithm='HS256')
        return self.token

    def verify_auth_token(self, token) -> dict or bool:
        try:
            decoded_token = jwt.decode(
                token, environ.get('SECRET_KEY'), algorithms="HS256",
                options={"require": ['exp', 'sub']}
            )
            return decoded_token
        except jwt.DecodeError:
            return False
        except  jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False

class GroupModel(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    datetime = db.Column(db.DateTime(timezone=True), default=func.now())
    group_user = db.relationship('GroupUserModel', backref='groups')

    def __repr__(self) -> str:
        return f'<Group name: {self.group_name}>'

    def create(self, groupname, description) -> object:
        newgroup = GroupModel(group_name=groupname, description=description)
        db.session.add(newgroup)
        db.session.commit()
        return newgroup

    def update(self):
        pass

    def delete(self, group):
        db.session.delete(group)
        db.session.commit()

class GroupUserModel(db.Model):
    __tablename__ = 'group_users'
    id = db.Column(db.Integer, primary_key=True)
    admin = db.Column(db.Boolean, default=False, nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    groupid = db.Column(db.Integer, db.ForeignKey('groups.id'))
    chat = db.relationship('ChatModel', backref='group_users')

    def __repr__(self) -> str:
        return f'<ID: {self.id}>'

    def create(self, userid, groupid, admin=False) -> object:
        group_users = GroupUserModel(userid=userid, groupid=groupid, admin=admin)
        db.session.add(group_users)
        db.session.commit()
        return group_users

    def update(self):
        pass

    def delete(self, group_user):
        db.session.delete(group_user)
        db.session.commit()

class ChatModel(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    groupid = db.Column(db.Integer, db.ForeignKey('group_users.id'))
    message = db.relationship('MessageModel', backref='chats')

    def __repr__(self) -> str:
        return f'<Chat ID: {self.id}>'

    def create(self):
        pass

    def update(self):
        pass

    def delete(self):
        pass

class MessageModel(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text(1000))
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.id'))
    datetime = db.Column(db.DateTime(timezone=True), default=func.now())

    def __repr__(self) -> str:
        return f'<Message: "{self.message[:20]}...">'

    def create(self):
        pass

    def update(self):
        pass

    def delete(self):
        pass
