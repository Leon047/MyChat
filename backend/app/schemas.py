from app import ma
from .models import UserModel, GroupModel, GroupUserModel


class UserSchema(ma.Schema):
    class Meta:
        model = UserModel
        fields = ('id', 'icon', 'username', 'email', 'is_active', 'last_login')

class GroupSchema(ma.Schema):
    class Meta:
        model = GroupModel
        fields = ('id', 'group_name', 'description')

class GroupUserSchema(ma.Schema):
    class Meta:
        model = GroupUserModel
        fields = ('id', 'userid', 'groupid', 'admin')
