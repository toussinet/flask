import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, json
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

from werkzeug.exceptions import abort

import jsonpickle

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
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
                return {"Message": 'Email already taken'}
            
                
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')




# @bp.route('/register', methods=('GET', 'POST'))
# def register():
#     if request.method == 'POST':
#         # username = request.form['username']
#         username = request.get_json()["username"]
#         password = request.get_json()["password"]
#         email = request.get_json()["email"]
#         db = get_db()
#         error = None

#         if not username:
#             error = 'Username is required.'
#         elif not password:
#             error = 'Password is required.'
#         elif not email:
#             error = 'Email is required.'

#         if error is None:
#             try:
#                 db.execute(
#                     "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
#                     (username, email, generate_password_hash(password)),
#                 )
#                 db.commit()
#             except db.IntegrityError:
#                 error = f"User {username} is already registered."
#                 return {"Message": 'Email already taken'}
            
                
#             else:
#                 # return redirect(url_for("auth.login"))
#                 data = {
#                     "Username": username,
#                     "Email": email
#                     }
#                 # response = jsonify(response=json.dumps(data),
#                 #                   status=200,
#                 #                   mimetype='application/json')
#                 # return response
#                 return jsonify(data), 200

#         # flash(error)

#     # return render_template('auth/register.html')
#     # return request.get_json()["username"]


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()

        if user is None:
            error = 'Incorrect email.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        
        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view 


@bp.route('/<int:id>/profile', methods=('GET', 'POST'))
@login_required
def profile(id):
    user = get_user(id)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        error = None

        if not username:
            error = 'Username is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE users SET username = ?, email = ?'
                ' WHERE id = ?',
                (username, email, id)
            )
            db.commit()
            success = "Updated successfully."
            flash(success)
            return redirect(url_for('auth.profile', id=id))

    return render_template('auth/profile.html', user=user)

def get_user(id):

    user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (id,)
        ).fetchone()
    if user is None:
        abort(404, f"User id {id} doesn't exist.")

    return user

#api
@bp.route('/<int:id>/user/get', methods=['GET'])
def get_user(id):

    user = get_db().execute(
            'SELECT * FROM users WHERE id = ?', (id,)
        ).fetchone()
    if user is None:
        abort(404, f"User id {id} doesn't exist.")
    res_list = list(enumerate(user))

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"]
    }


@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (id,))
    db.commit()
    logout()
    return redirect(url_for('auth.register'))

#api
@bp.route('/<int:id>/user/delete', methods=('DELETE',))
def delete_user(id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (id,))
    db.commit()
    return {"Message": f"User {id} deleted"}

#api
@bp.route('/<int:id>/user/update', methods=('PUT',))
def update_user(id):
    try:
        if request.method == 'PUT':
            # username = request.form['username']
            username = request.get_json()["username"]
            email = request.get_json()["email"]
        db = get_db()
        db.execute(
        'UPDATE users SET username = ?, email = ?'
        ' WHERE id = ?',
        (username, email, id)
        )
        db.commit()
        return {"Message": f"User {id} updated"}
    except:
        return {"Message": f"User {id} not found"}
        
        
