import mysql.connector
import os
from flask import Flask,request,jsonify,render_template,redirect,session,url_for
from flask_cors import CORS, cross_origin

app=Flask(__name__)
CORS(app,support_credencials=True,resource=r'/*',allow_headers='*',origins='*')

mydb=mysql.connector.connect(host='127.0.0.1',user='root',password='3005461Mo.',auth_plugin='mysql_native_password')
app.config['JSON_SORT_KEYS']=False
app.config['SECRET_KEY'] = 'secret_key'
mycursor = mydb.cursor(buffered=True)
mycursor.execute('CREATE DATABASE IF NOT EXISTS flask_db')
mycursor.execute('USE flask_db')
mycursor.execute("""CREATE TABLE IF NOT EXISTS user (id int(11) NOT NULL auto_increment,
    name VARCHAR(40),
   PRIMARY KEY (id))""")

@app.route('/new',methods=['GET','POST'])
def new():
    pass
@app.route('/',methods=['GET'])
def main():
    return render_template('teste.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        # Check if account exists using MySQL
        mycursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        # Fetch one record and return result
        account = mycursor.fetchone()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            # Redirect to some page
            if account[0] == 1:# ID do perfil do diretor
                return redirect(url_for('diretor'))
            elif account[0] == 2:# ID do perfil do financeiro
                return redirect(url_for('financeiro'))
            else: return  redirect(url_for('gestor'))# ID logado é dos gestores

        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Nome de Usuário/senha incorreto!'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg)

@app.route('/login/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)