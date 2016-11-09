from flask import Flask, render_template, request, redirect, session, flash, url_for
import re, md5

from flask.ext.bcrypt import Bcrypt
from mysqlconnection import MySQLConnector
from itertools import groupby

app = Flask(__name__)
app.secret_key = 'ThisIsSecret'
mysql = MySQLConnector('thewall')
bcrypt = Bcrypt(app)

emailRegex = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
passwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')

def validate():
    errors = 0
    #Check first name
    if request.form['first_name'] == '':
        flash('Name cannot be blank', 'first_nameError')
        errors += 1
        pass
    elif any(char.isdigit() for char in request.form['first_name']) == True:
        flash('Name cannot have numbers', 'first_nameError')
        errors += 1
        pass
    else:
        session['first_name'] = request.form['first_name']

    #Check last name
    if request.form['last_name'] == '':
        flash('Name cannot be blank', 'lastNameError')
        errors += 1
        pass
    elif any(char.isdigit() for char in request.form['last_name']) == True:
        flash('Name cannot have numbers', 'lastNameError')
        errors += 1
        pass
    else:
        session['last_name'] = request.form['last_name']

    #Check email
    if request.form['email'] == '':
        flash('Email cannot be blank', 'emailError')
        errors += 1
        pass
    elif not emailRegex.match(request.form['email']):
        flash('Invalid email address', 'emailError')
        errors += 1
        pass
    else:
        session['email'] = request.form['email']
    #Check password
    if request.form['password'] == '':
        flash('Password cannot be blank', 'passwordError')
        errors += 1
        pass
    elif len(request.form['password']) < 8:
        flash('Password must be greater than 8 characters', 'passwordError')
        errors += 1
        pass
    elif not passwordRegex.match(request.form['password']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'passwordError')
        errors += 1
        pass
    else:
        session['password'] = request.form['password']
    #Check confirmation password
    if request.form['confirmPassword'] == '':
        flash('Please confirm password', 'confirmPasswordError')
        errors += 1
        pass
    elif request.form['confirmPassword'] != request.form['password']:
        flash('Passwords do not match', 'confirmPasswordError')
        errors += 1
    else:
        session['confirmPassword'] = request.form['confirmPassword']
    #See if there are any errors
    if errors > 0:
        session['password'] = ''
        session['confirmPassword'] = ''
        return False
    else:
        return True

def validateLogin():
    errors = 0
     #Check email
    if request.form['email'] == '':
        flash('Email cannot be blank', 'emailError2')
        errors += 1
        pass
    elif not emailRegex.match(request.form['email']):
        flash('Invalid email address', 'emailError2')
        errors += 1
        pass
    else:
        session['email'] = request.form['email']
    #Check password
    if request.form['password'] == '':
        flash('Password cannot be blank', 'passwordError2')
        errors += 1
        pass
    elif len(request.form['password']) < 8:
        flash('Password must be greater than 8 characters', 'passwordError2')
        errors += 1
        pass
    elif not passwordRegex.match(request.form['password']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit', 'passwordError2')
        errors += 1
        pass
    else:
        session['password'] = request.form['password']

        #See if there are any errors
    if errors > 0:
        session['password'] = ''
        session['confirmPassword'] = ''
        return False
    else:
        return True

def setUserId():
    getUserId = "SELECT id FROM users WHERE email = '{}'".format(session['email'])
    getid = mysql.fetch(getUserId)
    session['id'] = getid[0]['id']
    return True

@app.route('/')
def index():
    try:
        if session['first_name'] == None:
            session['first_name'] = ''
    except KeyError:
        session['first_name'] = ''
    try:
        if session['lastName'] == None:
            session['lastName'] = ''
    except KeyError:
        session['last_name'] = ''
    try:
        if session['email'] == None:
            session['email'] = ''
    except KeyError:
        session['email'] = ''
    try:
        if session['password'] == None:
            session['password'] = ''
    except KeyError:
        session['password'] = ''
    try:
        if session['confirmPassword'] == None:
            session['confirmPassword'] = ''
    except KeyError:
        session['confirmPassword'] = ''
    try:
        if session['id'] == None:
            session['id'] = ''
    except KeyError:
        session['id'] = ''
    try:
        if session['loggedin'] == None:
            session['loggedin'] = False
    except KeyError:
        session['loggedin'] = False
    return render_template('index.html')

@app.route('/message/<message_id>/comment', methods=['POST'])
def commentData(message_id):
    if session['loggedin'] == False:
        return redirect('/')
    else:
        session['loggedin'] == True
        commentMessage = str(request.form['comment'])
        query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES ('{}', '{}', '{}', NOW(),NOW())".format(message_id, session['id'], commentMessage)
        mysql.run_mysql_query(query)
        return redirect('/wall')

@app.route('/message', methods=['POST'])
def messageData():
    if session['loggedin'] == False:
        return redirect('/')
    else:
        session['loggedin'] == True
        setUserId()
        postMessage = str(request.form['message'])
        escaped = re.escape(postMessage)
        query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES ('{}', '{}', NOW(), NOW())".format(session['id'], escaped)
        mysql.run_mysql_query(query)
        return redirect('/wall')

@app.route('/register', methods=['POST'])
def create():
    if validate() == False:
        session['loggedin'] = False
        return redirect('/')
    else:
        password = md5.new(request.form["password"]).hexdigest();
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES ('{}', '{}', '{}','{}', NOW(), NOW())".format(first_name, last_name, email, password)
        mysql.run_mysql_query(query)
        session['loggedin'] = True
        # session['password'] = ''
        # session['confirmPassword'] = ''
        return redirect('/wall')

@app.route('/login', methods=['POST'])
def validateLoginInfo():
    if validateLogin() == False:
        session['loggedin'] = False
        return redirect('/')
    else:
        password = md5.new(request.form['password']).hexdigest();
        email = request.form['email']
        select_query = "SELECT * FROM users WHERE users.password = '{}' AND users.email = '{}'".format(password, email);
        user = mysql.fetch(select_query)
        if user: 
            session['loggedin'] = True
            session['id'] = user[0]['id']
            session['first_name'] = user[0]['first_name']
            return redirect('/wall')
        else:
            flash('Incorrect password', 'passwordError2')
            return redirect('/')
    return redirect('/')

@app.route('/wall')
def wall():
    if session['loggedin'] == True:
        setUserId()
        messages = mysql.fetch("SELECT users.first_name, users.last_name, messages.user_id, messages.created_at, messages.message, messages.id AS message_id FROM users JOIN messages ON messages.user_id = users.id ORDER BY messages.created_at")
        comments = mysql.fetch("SELECT users.first_name, users.last_name, comments.created_at, comments.comment, comments.message_id AS mess_id FROM users JOIN messages ON users.id = messages.user_id JOIN comments ON messages.id = comments.message_id ORDER BY comments.created_at")
        return render_template('wall.html', messages=messages, comments=comments)
    else:
        return redirect('/')

@app.route('/delete/<message_id>', methods='POST')
def delete(message_id):
    if session['loggedin'] == True:
        deletemsg = "DELETE FROM messages WHERE id = '{}'".format(message_id)
        deletecmt = "DELETE FROM comments WHERE id = '{}'".format(message_id)
        mysql.run_mysql_query(deletecmt)
        mysql.run_mysql_query(deletemsg)
        return redirect('/wall')
    else:
        return redirect('/')

@app.route('/logout')
def logout():
    session['first_name'] = ''
    session['last_name'] = ''
    session['email'] = ''
    session['password'] = ''
    session['confirmPassword'] = ''
    session['userid'] = ''
    session['loggedin'] = False
    return redirect('/')
app.run(debug=True)