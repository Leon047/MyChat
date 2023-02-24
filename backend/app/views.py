from flask_restful import Resource
from flask import request, jsonify

from app import db
from .mixins import is_auth
from .models import UserModel, AuthTokensModel, GroupModel, GroupUserModel
from .schemas import UserSchema, GroupSchema, GroupUserSchema


class Registration(Resource):

    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        if username is None or password is None:
            return {'error': 'missing arguments'}, 400
        if UserModel.query.filter_by(username = username).first() is not None:
            return {'error': 'existing user'}, 404

        user = UserModel(username = username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        return {'username': user.username}, 201

class Auth(Resource):

    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        if username is None or password is None:
            return {'error': 'missing arguments'}, 400
        if UserModel.query.filter_by(username=username).first() is None:
            return {'error': 'User does not exist'}, 404
        user = db.one_or_404(db.select(UserModel).filter_by(username=username))
        pswrd_is_velid = user.verify_password(password, user.password_hash)
        if pswrd_is_velid:
            token = AuthTokensModel(userid=user.id)
            new_token = token.get_auth_token(user.id)
            if AuthTokensModel.query.filter_by(userid=user.id).first() is None:
                db.session.add(token)
                db.session.commit()
                return {'token': new_token}, 201
            else:
                AuthTokensModel.query.filter_by(userid=user.id).update(
                    dict(token=new_token)
                )
                db.session.commit()
                return {'token': new_token}, 201
        else:
            return {'error': 'wrong password'}, 404

class User(Resource):

    def get(self):
        auth_token = request.headers.get('auth_token')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        user = UserModel.query.filter_by(id=auth.get('sub')).first_or_404(
            description='User not found.'
        )
        users_schema = UserSchema()
        dump_user = users_schema.dump(user)
        return jsonify({'user': dump_user})

    def post(self):
        pass

    def delete(self):
        auth_token = request.headers.get('auth_token')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        user = UserModel.query.filter_by(id=auth.get('sub')).first_or_404(
            description='User not found.')
        user_model = UserModel()
        user_model.delete(user)
        return {}, 204

class Group(Resource):

    def get(self):
        auth_token = request.headers.get('auth_token')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        mygroup_list = GroupUserModel.query.filter_by(userid=auth.get('sub')).all()
        mygroups = []
        for i in mygroup_list:
            group = GroupModel.query.filter_by(id=i.groupid).first()
            mygroups.append(group)
        grouplist_schema = GroupSchema(many=True)
        dump_grouplist = grouplist_schema.dump(mygroups)
        return {'group_list': dump_grouplist}, 200

    def post(self):
        auth_token = request.headers.get('auth_token')
        group_name = request.json.get('group_name')
        group_description = request.json.get('description')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        if group_name == None:
            return {'group_name': 'missing argument'}, 404
        if GroupModel.query.filter_by(group_name=group_name).first() is None:
            group = GroupModel()
            group_schema = GroupSchema()
            new_group = group.create(groupname=group_name, description=group_description)
            dump_group = group_schema.dump(new_group)

            group_user = GroupUserModel()
            group_user.create(auth.get('sub'), new_group.id, True)
            return {'New group': dump_group}, 201
        else:
            return {'Error': 'The group already exists'}, 404

    def patch(self):
        pass

    def delete(self):
        auth_token = request.headers.get('auth_token')
        groupid = request.args.get('groupid')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        group = GroupModel.query.filter_by(groupid=groupid).first_or_404(
            description='Group not found.')
        # Delete grope
        delete_group = GroupModel()
        delete_group.delete(group)

        # Delete all group users
        group_userlist = GroupUserModel.query.filter_by(groupid=groupid).all()
        group_user = GroupUserModel()
        for user in group_userlist:
            group_user.delete(user)
        return {}, 204

class GroupUser(Resource):

        def get(self):
            auth_token = request.headers.get('auth_token')
            groupid = request.args.get('groupid')
            auth = is_auth(auth_token)
            if auth == False:
                return {'auth': 'token error'}, 404
            userlist = GroupUserModel.query.filter_by(groupid=groupid).all()
            userlist_schema = GroupUserSchema(many=True)
            dump_userlist = userlist_schema.dump(userlist)
            return {'group_users': dump_userlist}, 200

        def post(self):
            auth_token = request.headers.get('auth_token')
            groupid = request.json.get('groupid')
            userid = request.json.get('userid')
            auth = is_auth(auth_token)
            if auth == False:
                return {'auth': 'token error'}, 404
            group = GroupUserModel.query.filter_by(groupid=groupid).all()
            for i in group:
                if userid == i.userid:
                    return {'error': 'User already added'}, 404
            group_user = GroupUserModel()
            new_user = group_user.create(userid, groupid)
            user_schema = GroupUserSchema()
            dump_user = user_schema.dump(new_user)
            return {'new_user': dump_user}, 201

        def delete(self):
            auth_token = request.headers.get('auth_token')
            groupid = request.json.get('groupid')
            userid = request.json.get('userid')
            auth = is_auth(auth_token)
            if auth == False:
                return {'auth': 'token error'}, 404
            group = GroupUserModel.query.filter_by(groupid=groupid).all()
            for user in group:
                print(userid, userid==user.userid, user.admin==False)
                if userid == user.userid:
                    if user.admin == False:
                        group_user = GroupUserModel()
                        group_user.delete(user)
                        return {}, 204
                else:
                    return {'error': 'user is not found'}
            return {'error': 'you are a group administrator'}, 404

class UserFilter(Resource):

    def get(self):
        username = request.args.get('username')
        user_list = UserModel.query.filter_by(username=username).all()
        auth_token = request.headers.get('auth_token')
        auth = is_auth(auth_token)
        if auth == False:
            return {'auth': 'token error'}, 404
        if user_list == []:
            return {'filtered data': 'Not Found'}, 404
        else:
            users_schema = UserSchema(many=True)
            dump_user = users_schema.dump(user_list)
            return jsonify({'filtered data': dump_user})

class Chat(Resource):

    def get(self):
        pass

    def post(self):
        pass

    def delete(self):
        pass
