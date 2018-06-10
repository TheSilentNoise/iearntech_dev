from flask import Flask,render_template,redirect,url_for,session,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired,Email,Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,UserMixin,login_user,login_required,logout_user,current_user


from flask import session


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@127.0.0.1/Test'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized_callback():
    session['next_url'] = request.path
    return redirect('login')


############ models

class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(16),unique=True)
    email = db.Column(db.String(100),unique=True)
    password = db.Column(db.String(256))

    def is_authenticated(self):
        return False

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

############ forms


class Loginform(FlaskForm):
    username = StringField('username',validators=[InputRequired(),Length(min=8,max=16)])
    password = PasswordField('password',validators=[InputRequired(),Length(min=8,max=16)])
    remember = BooleanField('remember me')


class Registrationform(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=8, max=16)])
    email = StringField('email',validators=[InputRequired(), Email(message="Invalid Email ")])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=16)])


############ views


@app.route('/')
def index():
    if current_user.is_authenticated:
      session.permanent = True
      return render_template('index.html',name=current_user.username)
    return render_template('index.html')


@app.route('/login',methods=['GET','POST'])
def login():
    form = Loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            session['username'] = form.username.data
            if check_password_hash(user.password,form.password.data):
                login_user(user,remember=form.remember.data)
                #return redirect(url_for('dashboard',name=form.username.data))
                return redirect(url_for('dashboard'))
       # return '<h1>' + form.username.data + '</h1>'
        return render_template('login.html',form=form,message="Invalid username or password")
    return render_template('login.html',form=form)



@app.route('/signup',methods=['GET','POST'])
def signup():
    form = Registrationform()
    if form.validate_on_submit():
     try:
        session['username'] = form.username.data
        hashed_pwd = generate_password_hash(form.password.data,method='sha256')
        new_user = User(username=form.username.data ,email=form.email.data,password=hashed_pwd)
        db.session.add(new_user)
        db.session.commit()
        return redirect( url_for('login'))
     except Exception as e:
        return '<h1>New user not created..</h1>'
    return render_template('signup.html',form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated:
      session.permanent = True
      return render_template('dashboard.html',name=current_user.username)
    return redirect('login')
    #if not current_user.is_active:
     #   return redirect('login')
    #return render_template('dashboard.html',name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    print("starting application....")
    app.run(debug=True)