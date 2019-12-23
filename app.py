import os
import sqlite3
from flask import Flask, render_template, request, url_for,redirect, session
from flask.wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from app import db, bcrypt
import subprocess

app = Flask(__name__)

csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'Itissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////User/Documents/Assignment3/database.db'
app.config('CSRF_ENABLED') = True
session.cookie_httponly = 1
app.config['SECRET_KEY'] = 'secret' socketio = SocketIO(app)
call(["ls", "-l"])
Bootstrap(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMinin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
	  username = db.Column(db.String(15), unique=True)
	  password = db.Column(db.String(80), unique=True)
	  2fa = db.Column(db.String(20), unique=True)
    #password = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)

   # def is_active(self):
    #   return True

   # def get_id(self):
   #    return self.register

   # def is_authenticated(self):
   #     return self.authenticated

class LoginForm(FlaskForm)
username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
password = StringField('password, validators=[InputRequired(), Length(min=8, max=80)])
2fa = StringField('2fa', validators=[DataRequired(), Length(min=6, max=10)])

class RegistrationForm(FlaskForm):
username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
password = StringField('password', validators=[InputRequired(), Length(min=8, max=80)])
2fa = StringField('2fa', validators=[DataRequired(), Length(min=6, max=10)]) 
    
@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(username)

@app.route('/')
def index():
	return render_template('index.html')                       

@app.route("/login", methods=["GET", "POST"])
def login():
form = LoginForm()
	if form.validate_on_submit():
		#return '<h1>' + form.username.data + '' + form.password.data + </h1 >

		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user-password, form.password.data):
			login_user(user, 2fa=form.2fa.data)
			return redirect(url_for('index'))

		return '<h1> Invalid Information</h1>'
	return render_template('login.html', form=form)

@app.route('/register', method=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
	hashed_password = generate_password_hash(form.password.data, method='sha256')
	new_user = User(username=form.username.data, password=hashed_password, 2fa=form.2fa.data)
	db.sesson.add(new_user)
	db.session.commit()
	return '<h1>New user has been created</h1>'	
#	return '<h1>' + form.username.data + '' + form.password.data + '' + form.2fa.data + </h1 >

	return render_template('register.html', form=form)    
                       
print db
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.get(form.2fa.data)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                user.authenticated = True
                db.session.add(user)
                db.session.commit()
                login_user(user, remember=True)
               # return redirect(url_for("history"))
    return render_template("login.html", form=form)

@app.route("/logout", methods=["GET"])
@login_required
def logout():
   # user = current_user
   # user.authenticated = False
   # db.session.add(user)
   # db.session.commit()
    logout_user()
    return render_template("index.html")
                       
if __name__ == '__main__':
    app.run(debug=True)
