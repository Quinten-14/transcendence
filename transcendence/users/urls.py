from django.urls import path
from . import views

urlpatterns = [
        path('login_user', views.login_user, name="login"),
        path('signup_user', views.signup_user, name="signup"),
        path('logout_user', views.logout_user, name="logout"),
        path('2fa', views.two_factor_auth, name="2fa"),
        path('delete_user', views.delete_user, name="delete"),
        path('intra', views.loginIntra, name="intra"),
        path('auth_callback', views.auth_callback, name='auth_callback'),
        path('confirmOtp', views.confirmOtp, name='confirmOtp'),
        path('player2auth', views.player2auth, name='player2auth'),
        path('submit-game-data', views.submit_game_data, name='submit-game-data'),
        path('fillResetPassEmail', views.fillResetPassEmail, name='fillResetPassEmail'),
        path('reset_password', views.reset_password, name='reset_password'),
]
