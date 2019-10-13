from flask import Flask, render_template, redirect, url_for, request, send_from_directory, session, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, BooleanField, FileField, SubmitField, ValidationError, SelectField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import timedelta
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sv.db'

mail = Mail(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=5)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.congif['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.congif['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return none
        return User.query.get(user_id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('Company Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class RequestRestForm(FlaskForm):
    style={'class': 'ourClasses', 'style': 'background-image: linear-gradient(#022127, #37304c);border:none;font-family: "Roboto", sans-serif;font-size: 16px;font-weight: 400;color:white;padding-left:20px;padding-right:20px;'}
    email = StringField('Company Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    submit = SubmitField('Request Password Reset',render_kw=style)

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    style={'class': 'ourClasses', 'style': 'background-image: linear-gradient(#022127, #37304c);border:none;font-family: "Roboto", sans-serif;font-size: 16px;font-weight: 400;color:white;padding-left:20px;padding-right:20px;'}
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password',render_kw=style)
    
class UploadForm(Form):
    style={'class': 'ourClasses', 'style': 'background-color: #E07619;border: 2px solid #E07619;color:white;border-radius: 5px;font-family: "Roboto", sans-serif;font-size: 16px;font-weight: 400;box-shadow: 0px 0px 15px -7px rgba(0,0,0,0.75);'}
    style1={'class': 'ourClasses', 'style': 'border-color: #E07619 !important;'}
    video_file = FileField('Upload Video Here:',validators=[InputRequired()])
    game = SelectField('Select Sports', choices=[('Soccer', 'Soccer'), ('Basketball', 'Basketball'), ('Rugby', 'Rugby'), ('Tennis', 'Tennis'), ('Others', 'Others')], validators=[InputRequired()],render_kw=style1)
    feature = SelectField('Select Feature', choices=[('Action and Event Tagging', 'Action and Event Tagging'), ('Player Tracker', 'Player Tracker'), ('Body Posture Analysis', 'Body Posture Analysis'), ('Quick Match Highlights', 'Quick Match Highlights')], validators=[InputRequired()],render_kw=style1)
    description = TextAreaField('Description about the Video', validators=[InputRequired()],render_kw=style1)
    submit = SubmitField('Upload',render_kw=style)

    def validate_video_file(self, field):
        if field.data.filename[-4:].lower() != '.mp4':
            raise ValidationError('Invalid file extension')

@app.route('/')
def index():
    form = RegisterForm()
    return render_template('index.html',form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    #After Verify the validity of username and password
    session.permanent = True
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                session['logged_in'] = True
                return redirect(url_for('dashboard'))

        flash(u'Invalid username or password', 'error')
        return redirect(url_for('login'))
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('index.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/feature', methods=['GET', 'POST'])
@login_required
def feature():
    return render_template('feature.html', name=current_user.username)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    video = None
    form = UploadForm()
    if form.validate_on_submit():
        video = 'sv_uploads/' + form.video_file.data.filename
        form.video_file.data.save(os.path.join(app.static_folder, video))

    return render_template('upload.html', name=current_user.username, form=form, video=video)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session['logged_in'] = False
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)