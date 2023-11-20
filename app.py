# -*- coding: utf-8 -*-
import time
from collections.abc import Callable, Iterable, Mapping
from threading import Thread
from typing import Any
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

class second(Thread):
    def __init__(self):
        super().__init__()
        self.value = 0

    def run(self):
        while True:
            time.sleep(1)
            self.value += 1

th = second()
th.daemon = True
th.start()

app = Flask(__name__)
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SECRET_KEY'] = "SECRETKEYTHATNOBADYKNOW"
db.init_app(app)
bcrypt = Bcrypt()

login_manager = LoginManager()
login_manager.init_app(app=app)
login_manager.login_view = "login"

@app.before_request
def before():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class Status(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    productName = db.Column(db.String(20), nullable=False)


class StatusForm(FlaskForm):
    productName = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholde":"product name"})
    submit = SubmitField("Set")

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route("/api_page", methods=['GET','POST'])
def api_page():
    msg = {'text': 'Привет, это JSON-сообщение от сервера!<br/>'}
    print("data send")
    return jsonify(msg)


@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect("dashboard")
    return render_template("login.html", form=form)


@app.route('/status', methods=['GET', 'POST'])
def status():
    form = StatusForm()
    if form.validate_on_submit():
        new_status = Status(productName=form.productName.data)
        db.session.add(new_status)
        db.session.commit()
    return render_template("status.html", form=form)


@app.route('/status_view', methods=['GET', 'POST'])
def statusView():
    form = Status.query.with_entities(Status.productName).all()
    print(form)
    return render_template("statusView.html", form=form)


@app.route("/")
def home():
    return render_template("index.html")

@login_manager.unauthorized_handler
def unauthorized_callback():
    return render_template("unauthorised.html")

@app.route("/dashboard", methods=['POST', 'GET'])
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/logout",  methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect("login")


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html", form=form)

@app.route("/load.html", methods=['POST', 'GET'])
def load():
    form = [th.value]
    return render_template("load.html", form=form)

@app.route('/test')
def test_route():
    return render_template('test.html')


@app.route("/bets", methods=['POST','GET'])
def bets():
    return render_template("betlist.html")


if __name__ == "__main__":
    app.run(debug=True)

r"""py -3.9 -m pip install flask    pip 23.2.1
Requirement already satisfied: flask in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (2.3.2)
Requirement already satisfied: Werkzeug>=2.3.3 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (2.3.4)
Requirement already satisfied: Jinja2>=3.1.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (3.1.2)
Requirement already satisfied: itsdangerous>=2.1.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (2.1.2)      
Requirement already satisfied: click>=8.1.3 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (8.1.3)
Requirement already satisfied: blinker>=1.6.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (1.6.2)
Requirement already satisfied: importlib-metadata>=3.6.0 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (6.6.0)Requirement already satisfied: colorama in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from click>=8.1.3->flask) (0.4.6)   
Requirement already satisfied: zipp>=0.5 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from importlib-metadata>=3.6.0->flask) (3.15.0)
Requirement already satisfied: MarkupSafe>=2.0 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from Jinja2>=3.1.2->flask) (2.1.2)
Create example.db
1. python
2. from app import db
3. db.create_all()
4. exit()"""