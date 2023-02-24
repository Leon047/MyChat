from .models import AuthTokensModel


def is_auth(auth_token) -> object or bool:
    auth_user = AuthTokensModel()
    is_auth = auth_user.verify_auth_token(auth_token)
    if is_auth:
        return is_auth
    else:
        return False
