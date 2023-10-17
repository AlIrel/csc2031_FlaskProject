from flask import Blueprint, render_template, redirect, url_for, flash
from models import User
from users.forms import RegisterForm
from app import db
users_blueprint = Blueprint('users', __name__, template_folder='templates')


@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("Username already exists")
            return render_template('users/register.html', form=form)

        new_user = User(username=form.username.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('users.login'))

    return render_template('users/register.html', form=form)


@users_blueprint.route('/login')
def login():
    return render_template('users/login.html')


@users_blueprint.route('/account')
def account():
    return render_template('users/account.html')
