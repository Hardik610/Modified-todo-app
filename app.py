import json
import os
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

import jwt
import flask_bcrypt
from flask import Flask, render_template, url_for, redirect, request, Response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from datetime import datetime, timedelta, date
from apscheduler.schedulers.blocking import BlockingScheduler

schedule_mail = BlockingScheduler()
app = Flask(__name__)
db = SQLAlchemy(app)
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
INCOMING_DATE_FMT = '%d/%m/%Y %H:%M:%S'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
sender_address = os.environ.get('SENDER_EMAIL')
email_password = os.environ.get('EMAIL_PASSWORD')
mail_content = '''Hello,
This is a mail regarding due date of a pending Task, Please complete it before due date.
Thank You'''


def send_mail(email):
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = email
    message['Subject'] = 'Alert for due date of a task'
    message.attach(MIMEText(mail_content, 'plain'))
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_address, email_password)
    text = message.as_string()
    server.sendmail(sender_address, email, text)
    server.quit()
    schedule_mail.shutdown(wait=False)
    return "Sent"


@login_manager.user_loader
def load_user(userID):
    return User.query.get(int(userID))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.CHAR(60), nullable=False)
    email = db.Column(db.Unicode, nullable=False)
    token = db.Column(db.Unicode, nullable=False)
    date_joined = db.Column(db.DateTime, nullable=False)
    task = db.relationship("Task", back_populates="user")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.date_joined = datetime.now()
        self.token = secrets.token_urlsafe(64)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Unicode)
    creation_date = db.Column(db.DateTime, nullable=False)
    due_date = db.Column(db.DateTime)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", back_populates="task")

    subtask = db.relationship("Subtask", back_populates="task")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.creation_date = datetime.now()


class Subtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode, nullable=False)
    description = db.Column(db.Unicode)
    completed = db.Column(db.Boolean, default=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    task = db.relationship("Task", back_populates="subtask")


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    email = StringField(validators=[InputRequired()], render_kw={"placeholder": "Email"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exist, Choose different username")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            print(token)
            print(app.config['SECRET_KEY'])
            final = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            print(final)
            current_user = User.query.filter_by(username=final['username']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/')
def home():  # put application's code here
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_info = User.query.filter_by(username=form.username.data).first()
        if user_info:
            if flask_bcrypt.check_password_hash(user_info.password, form.password.data):
                login_user(user_info)
                token = jwt.encode(
                    {'username': user_info.username, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                    app.config['SECRET_KEY'])
                return jsonify({'token': token})
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = flask_bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/api/v1/task', methods=['GET', 'POST'])
@token_required
def create_task(current_user):
    username = current_user.username
    if request.method == 'GET':
        try:
            user_info = User.query.filter_by(username=username).first()
            filtered_task = Task.query.filter_by(user_id=user_info.id).order_by('due_date')
            data = []
            for task in filtered_task:
                data.append({'name': task.name, 'description': task.description, 'due_date': task.due_date,
                             'completed': task.completed})
            return jsonify(data)
        except Exception as e:
            print('Error: ', e)
            return None
    else:
        user_info = User.query.filter_by(username=username).first()
        if user_info:
            task = Task(
                name=request.form['name'],
                description=request.form['description'],
                creation_date=datetime.now(),
                due_date=datetime.strptime(request.form['due_date'], INCOMING_DATE_FMT) if request.form[
                    'due_date'] else None,
                user_id=user_info.id,
            )
            db.session.add(task)
            db.session.commit()
            output = {'msg': 'posted'}
            response = Response(
                mimetype="application/json",
                response=json.dumps(output),
                status=201
            )
            return response
        return "User not found"


@app.route('/api/v1/searchTask', methods=['GET'])
@token_required
def search_task(current_user):
    title = request.args.get('title')
    task = Task.query.filter_by(name=title).first()
    data = {'name': task.name, 'description': task.description, 'due_date': task.due_date, 'completed': task.completed}
    return jsonify(data)


@app.route('/api/v1/getTask', methods=['GET'])
@token_required
def get_task(current_user):
    status = request.args.get('status', default=False, type=lambda v: v.lower() == 'true')
    tasks = Task.query.filter_by(completed=bool(status))
    data = []
    for task in tasks:
        data.append({'name': task.name, 'description': task.description, 'due_date': task.due_date,
                     'completed': task.completed})
    return jsonify(data)


@app.route('/api/v1/completeTask', methods=['GET'])
@token_required
def complete_task(current_user):
    task_id = request.args.get('task_id')
    task = Task.query.filter_by(id=task_id).first()
    task.completed = True
    db.session.commit()
    subtasks = Subtask.query.filter_by(task_id=task_id)
    for subtask in subtasks:
        subtask.completed = True
    db.session.commit()
    return "Task completed with subtask"


@app.route('/api/v1/filterTask', methods=['GET'])
@token_required
def filter_task(current_user):
    username = current_user.username
    filter_task_option = request.args.get('filter')
    user_info = User.query.filter_by(username=username).first()
    filtered_task = Task.query.filter_by(user_id=user_info.id)
    today = date.today()
    weekday = today.weekday()
    mon = today - timedelta(days=weekday)
    mon = datetime.combine(mon, datetime.min.time())
    sun = today + timedelta(days=(6 - weekday))
    sun = datetime.combine(sun, datetime.max.time())
    filter_task_arr = []
    if filter_task_option == 'Today':
        tod = datetime.now()
        today_filter = tod.replace(hour=23, minute=59, second=59)
        for task in filtered_task:
            if task.due_date <= today_filter:
                filter_task_arr.append(task)
    elif filter_task_option == 'This Week':
        print(mon, sun)
        for task in filtered_task:
            if sun >= task.due_date >= mon:
                filter_task_arr.append(task)
    elif filter_task_option == 'Next Week':
        mon = mon + timedelta(days=7)
        sun = sun + timedelta(days=7)
        print(mon, sun)
        for task in filtered_task:
            if sun >= task.due_date >= mon:
                filter_task_arr.append(task)
    elif filter_task_option == 'Overdue':
        for task in filtered_task:
            if task.due_date > datetime.now():
                filter_task_arr.append(task)
    data = []
    for task in filter_task_arr:
        data.append({'name': task.name, 'description': task.description, 'due_date': task.due_date,
                     'completed': task.completed})
    return jsonify(data)


@app.route('/api/v1/<task>/setAlert', methods=['GET'])
@token_required
def set_alert(current_user, task):
    hours_before_due_date = request.args.get('hours')
    username = current_user.username
    user_info = User.query.filter_by(username=username).first()
    task_info = Task.query.filter_by(name=task).first()
    alert_time = task_info.due_date - timedelta(hours=int(hours_before_due_date))
    schedule_mail.add_job(send_mail, 'date', run_date=alert_time, args=[user_info.email])
    schedule_mail.start()
    return "Mail Sent"


@app.route('/api/v1/<task>/subtask', methods=['GET', 'POST'])
@token_required
def create_subtask(current_user, task):
    if request.method == 'GET':
        try:
            task_info = Task.query.filter_by(name=task).first()
            subtasks = Subtask.query.filter_by(task_id=task_info.id)
            data = []
            for subtask in subtasks:
                data.append({'name': subtask.name, 'description': subtask.description, 'completed': subtask.completed})
            return jsonify(data)
        except Exception as e:
            print('Error: ', e)
            return None
    else:
        task_info = Task.query.filter_by(name=task).first()
        if task_info:
            subtask = Subtask(
                name=request.form['name'],
                description=request.form['description'],
                task_id=task_info.id,
            )
            db.session.add(subtask)
            db.session.commit()
            output = {'msg': 'posted'}
            response = Response(
                mimetype="application/json",
                response=json.dumps(output),
                status=201
            )
            return response
        return "User not found"


if __name__ == '__main__':
    app.run()
