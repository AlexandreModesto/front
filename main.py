from datetime import timedelta
import mysql.connector
from mysql.connector import Error
import os, requests
from flask import Flask,request,jsonify,render_template,redirect,session,url_for
from flask_cors import CORS, cross_origin
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from forms import *

app=Flask(__name__)
CORS(app,support_credencials=True,resource=r'/*',allow_headers='*',origins='*')
app.config['JSON_SORT_KEYS']=False
app.config['SECRET_KEY'] = 'secret_key'
app.config['SESSION_PERMANENT'] = True # Sessões permanentes (True) ou temporárias (False)
app.config['SESSION_USE_SIGNER'] = True
csrf=CSRFProtect(app)
def start_connection():
    try:
        mydb=mysql.connector.connect(host='127.0.0.1',user='root',password='3005461Mo.',auth_plugin='mysql_native_password')
        if mydb.is_connected():
            mycursor = mydb.cursor(buffered=True)
            # mycursor.execute('CREATE DATABASE IF NOT EXISTS flask_db')
            mycursor.execute('USE flask_db')
            # mycursor.execute("""CREATE TABLE IF NOT EXISTS users (id int(11) NOT NULL auto_increment,
            #     username VARCHAR(40),password VARCHAR(40),player_id BIGINT,
            #    PRIMARY KEY (id))""")
            # mycursor.execute("ALTER TABLE users ADD FOREIGN KEY(player_id) REFERENCES player(id)")
            return mydb,mycursor
    except Error as e:
        print(e)
    return None

#########################################################################################################
####################                CONFIG SESSION ABOVE                  ################################
#########################################################################################################


@app.route('/new',methods=['GET','POST'])
def new():
    msg=''
    form=SignInForm()
    if form.validate_on_submit():
        username= form.username.data
        password=form.password.data

        mydb,mycursor=start_connection()

        mycursor.execute("INSERT INTO users (username,password) VALUES (%s,%s)",(username,password))
        mydb.commit()
        msg=f"Usuário {username} criado com sucesso"
        return render_template("new.html",msg=msg,form=form)
    return render_template("new.html",form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=''
    form=LoginForm()
    # Check if "username" and "password" POST requests exist (user submitted form)
    if form.validate_on_submit():
        # Create variables for easy access
        username = form.username.data
        password = form.password.data
        # Check if account exists using MySQL
        mydb, mycursor = start_connection()
        mycursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = mycursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['logged_in'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            session.permanent=True
            app.permanent_session_lifetime=timedelta(minutes=30)
            # Redirect to some page
            return redirect(url_for('main'))# ID logado é dos gestores

        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Nome de Usuário/senha incorreto!'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg,form=form)

@app.route('/login/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('logged_in', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

#########################################################################################################
####################                USER SESSION ABOVE                  #################################
#########################################################################################################

@app.route('/',methods=['GET'])
def main():
    return render_template('teste.html')

@app.route('/new-player',methods=['GET','POST'])
def new_player():
    if 'logged_in' in session:
        form=NewPlayer()
        if form.validate_on_submit():
            playerName=form.playerName.data
            data={
                'playerName':playerName,
                'userId':session['id']
            }
            response = requests.post('http://localhost:8080/player/new',json=data)
            if response.status_code == 200:
                response_data = response.json()
                mydb, mycursor = start_connection()
                mycursor.execute("UPDATE users SET player_id =  %s WHERE id = %s",(response_data,session['id']))
                mydb.commit()
                return redirect(url_for('main'))
        return render_template('new_player.html',form=form)
    else:return redirect(url_for('login'))



if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)