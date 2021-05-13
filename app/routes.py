from app import app, db, bcrypt
from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, current_user, logout_user
from app.forms import RegisterForm, LoginForm
from app.models import UserModel


@app.route('/')
@login_required
def index():
    title = 'home'
    return render_template('index.html', title=title)


@app.route('/register',  methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    title = 'register'
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = bcrypt.generate_password_hash(form.password.data)

        user = UserModel(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Congrats, registration success', category='success')
        return redirect(url_for('login'))
    return render_template('register.html', title=title, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    title = 'login'
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data

        user = UserModel.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember)
            flash('Login success', category='success')
            return redirect(url_for('index'))
        flash('User not exists or password not match', category='danger')
    return render_template('login.html', title=title, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))