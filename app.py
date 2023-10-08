from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, redirect, url_for, request
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SECRET_KEY'] = "SECRETKEYTHATNOBADYKNOW"
db.init_app(app)
bcrypt = Bcrypt()



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


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


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=['GET',' POST'])
def login():
    form = LoginForm()
    return render_template("login.html", form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    print(1)
    if form.validate_on_submit():
        print(1)
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html", form=form)


@app.route('/test')
def test_route():
    user_details = {
        'name': 'John',
        'email': 'john@doe.com'
    }

    return render_template('test.html', user=user_details)


if __name__ == "__main__":
    app.run(debug=True)

"""py -3.9 -m pip install flask    pip 23.2.1
Requirement already satisfied: flask in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (2.3.2)
Requirement already satisfied: Werkzeug>=2.3.3 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (2.3.4)
Requirement already satisfied: Jinja2>=3.1.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (3.1.2)
Requirement already satisfied: itsdangerous>=2.1.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (2.1.2)      
Requirement already satisfied: click>=8.1.3 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (8.1.3)
Requirement already satisfied: blinker>=1.6.2 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (1.6.2)
Requirement already satisfied: importlib-metadata>=3.6.0 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from flask) (6.6.0)Requirement already satisfied: colorama in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from click>=8.1.3->flask) (0.4.6)   
Requirement already satisfied: zipp>=0.5 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from importlib-metadata>=3.6.0->flask) (3.15.0)
Requirement already satisfied: MarkupSafe>=2.0 in c:\users\negmatov\appdata\local\programs\python\python39\lib\site-packages (from Jinja2>=3.1.2->flask) (2.1.2)"""
