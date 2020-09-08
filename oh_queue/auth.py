from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_oauthlib.client import OAuth, OAuthException

from werkzeug import security

from oh_queue.models import db, User

auth = Blueprint('auth', __name__)
auth.config = {}


oauth = OAuth()

@auth.record
def record_params(setup_state):
    app = setup_state.app
    server_url = app.config.get('OK_SERVER_URL')

    auth.ok_auth = oauth.remote_app(
        'google',
        consumer_key=app.config.get('GOOGLE_ID'),
        consumer_secret=app.config.get('GOOGLE_SECRET'),
        request_token_params={
            'scope': 'email',
            'state': lambda: security.gen_salt(10)
        },
        base_url='https://www.googleapis.com/oauth2/v1/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
    )
    #auth.debug = app.config.get('DEBUG')

    @auth.ok_auth.tokengetter
    def get_access_token(token=None):
        return session.get('access_token')

login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized():
    session['after_login'] = request.url
    return redirect(url_for('auth.login'))

def authorize_user(user):
    login_user(user, remember=True)
    after_login = session.pop('after_login', None) or url_for('index')
    # TODO validate after_login URL
    return redirect(after_login)

def user_from_email(name, email, is_staff):
    """Get a User with the given email, or create one."""
    from oh_queue.course_config import get_course
    user = User.query.filter_by(email=email, course="HKN").one_or_none()
    if not user:
        user = User(name=name, email=email, course="HKN", is_staff=is_staff)
    else:
        user.name = name
        user.is_staff = is_staff
        user.course = "HKN"

    db.session.add(user)
    db.session.commit()
    return user

@auth.route('/login/')
def login():
    callback = url_for(".authorized", _external=True)
    return auth.ok_auth.authorize(callback=callback)

@auth.route('/assist/')
def try_login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    callback = url_for(".authorized", _external=True)
    return auth.ok_auth.authorize(callback=callback)

@auth.route('/login/authorized')
def authorized():
    from oh_queue.course_config import get_endpoint
    try:
        auth_resp = auth.ok_auth.authorized_response()
        if auth_resp is None:
            message = 'Invalid Ok response: %s' % (message)
            return redirect(url_for('error', message=message))
    except OAuthException as ex:
        message = str(ex)
        return redirect(url_for('error', message=message))

    token = auth_resp['access_token']
    session['access_token'] = (token, '')  # (access_token, secret)

    info = auth.ok_auth.get('userinfo').data

    email = info['email']

    if 'berkeley.edu' not in email:
        message = 'UC Berkeley email required to sign up.'
        return redirect(url_for('index', message=message))
    
    name = email[:email.index("@")]
    is_staff = 'hkn.eecs.berkeley.edu' in email

    user = user_from_email(name, email, is_staff)
    return authorize_user(user)

@auth.route('/logout/')
def logout():
    logout_user()
    session.pop('access_token', None)
    return redirect(url_for('index'))

@auth.route('/testing-login/')
def testing_login():
    if not auth.debug:
        abort(404)
    callback = url_for(".testing_authorized")
    return render_template('login.html', callback=callback)

@auth.route('/testing-login/authorized', methods=['POST'])
def testing_authorized():
    if not auth.debug:
        abort(404)
    form = request.form
    is_staff = form.get('is_staff') == 'on'
    user = user_from_email(form['name'], form['email'], is_staff)
    return authorize_user(user)

def init_app(app):
    app.register_blueprint(auth)
    login_manager.init_app(app)


