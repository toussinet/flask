import os
import sqlite3
from flask import Flask
from flask import (
    flash, g, redirect, render_template, request, session, url_for,current_app
)
import click
import json
from werkzeug.security import check_password_hash, generate_password_hash
app = Flask ( __name__ ) # means that your app name will be the same as the file

app.config.from_object(__name__)#loadconfigfromthisfileapp.py
#Loaddefaultconfigandoverrideconfigfromanenvironmentvariable

app.config.from_mapping(
    DATABASE=os.path.join(app.root_path,'flaskr.db'),
    SECRET_KEY='developmentkey',
    USERNAME='admin',
    PASSWORD='default'
)

app.config.from_envvar('FLASKR_SETTINGS',silent=True)

DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db



def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()
        
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


# @click.command('init-db')
# def init_db_command():
#     """Clear the existing data and create new tables."""
#     init_db()
#     click.echo('Initialized the database.')
    
def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv
    
# @app.route ( '/')
# def index() :
#     return("My home page")
@app.route('/')
def index():
    db = get_db()
    users = db.execute(
        'SELECT * from users'
    ).fetchall()
    return render_template('index.html', users=users)

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not email:
            error = 'Email is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("login"))

        flash(error)

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()
        print('Response:: ', json.dumps(user, indent=4))

        if user is None:
            error = 'Incorrect email.'
        elif not check_password_hash(user[-1], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user[0]
            return redirect(url_for('index'))

        flash(error)

    return render_template('login.html')


