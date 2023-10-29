from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Change to your preferred database
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    tweets = db.relationship('Tweet', backref='author', lazy=True)

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])

    # Define a custom validation function for email
    def validate_email(self, field):
        if not field.data.endswith('@muj.manipal.edu'):
            raise ValidationError('Only MUJ Manipal email addresses are allowed.')


class TweetForm(FlaskForm):
    content = TextAreaField('Tweet', validators=[InputRequired(), Length(max=280)])

@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        tweets = Tweet.query.order_by(Tweet.id.desc()).all()
        form = TweetForm()  # Create a TweetForm instance
        return render_template('home.html', user=user, tweets=tweets, form=form)  # Provide the form variable
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/post_tweet', methods=['POST'])
def post_tweet():
    if 'user_id' in session:
        form = TweetForm()
        if form.validate_on_submit():
            content = form.content.data
            user_id = session['user_id']
            tweet = Tweet(content=content, user_id=user_id)
            db.session.add(tweet)
            db.session.commit()
            flash('Tweet posted successfully!', 'success')
    return redirect(url_for('home'))
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

