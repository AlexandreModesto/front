from datetime import timedelta
import mysql.connector
from mysql.connector import Error
import os, requests, bcrypt
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
            #     username VARCHAR(40),password VARCHAR(60),player_id BIGINT,
            #     slot_1 VARCHAR(40) DEFAULT("+"),slot_2 VARCHAR(40) DEFAULT("+"),slot_3 VARCHAR(40) DEFAULT("+"),
            #    PRIMARY KEY (id))""")
            return mydb,mycursor
    except Error as e:
        print(e)
    return None

#########################################################################################################
####################                CONFIG SESSION ABOVE                  ################################
#########################################################################################################


@app.route('/signin',methods=['GET','POST'])
def signIn():
    msg=''
    form=SignInForm()
    if form.validate_on_submit():
        username= form.username.data
        password1=form.password1.data
        password2=form.password2.data

        if password1 == password2:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), salt)

            mydb,mycursor=start_connection()

            mycursor.execute("INSERT INTO users (username,password) VALUES (%s,%s)",(username,hashed_password.decode('utf-8')))
            mydb.commit()

            session['logged_in'] = True
            session['id'] = mycursor.lastrowid
            session['username'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)

            mycursor.close()
            mydb.close()

            msg=f"Usuário {username} criado com sucesso"
            return redirect(url_for("select_player"))

        else:
            msg = "Senhas não são iguais"
    return render_template("signIn.html",msg=msg,form=form)

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
        mycursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        # Fetch one record and return result
        account = mycursor.fetchone()
        mycursor.close()
        mydb.close()
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            if bcrypt.checkpw(password.encode('utf-8'),account[2].encode('utf-8')):
                session['logged_in'] = True
                session['id'] = account[0]
                session['username'] = account[1]
                session.permanent=True
                app.permanent_session_lifetime=timedelta(minutes=30)
                # Redirect to some page
                return redirect(url_for('main'))# ID logado é dos gestores
            else:msg='senha inválida'
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Nome de Usuário não encontrado!'
    # Show the login form with message (if any)
    return render_template('login.html', msg=msg,form=form)

@app.route('/login/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('logged_in', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop("player_id",None)
    # Redirect to login page
    return redirect(url_for('login'))

#########################################################################################################
####################                LOGIN SESSION ABOVE                  ################################
#########################################################################################################

@app.route('/',methods=['GET'])
def main():
    return render_template('teste.html')

@app.route("/player-slot",methods=["GET","POST"])
def select_player():
    if not 'logged_in' in session:
        return redirect(url_for("login"))
    else:
        form=PlayerSlotsForm()
        mydb, mycursor = start_connection()
        mycursor.execute(f"SELECT * FROM users WHERE id = %s",(session['id'],))
        query=mycursor.fetchone()
        mycursor.close()
        mydb.close()
        slots={}
        count=-3
        while count <0:
            aux=query[count]
            if not aux=="+":
                slot=aux.split(",")
                slots[slot[1]]=slot[0]
            else:slots[f'+{count}']="+"
            count+=1
        if form.validate_on_submit():
            selected_slot=request.form.get('selected')
            if not selected_slot[0] == "+":
                session["player_id"]=selected_slot
            else:
                return redirect(url_for("new_player"))
            return redirect(url_for('main'))
        return render_template("player_slots.html",slots=slots,form=form)



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
                mycursor.close()
                mydb.close()
                session['player_id'] = response_data
                return redirect(url_for('main'))
        return render_template('new_player.html',form=form)
    else:return redirect(url_for('login'))

@app.route("/info/<id>",methods=['GET'])
def player_info(id):
    response = requests.get(f'http://localhost:8080/player/info/{id}')
    print(response.status_code)
    if response.status_code == 200:
        return render_template('info_player.html',data=response.json())
    else:
        return render_template('info_player.html',msg='Player não encontrado')

#########################################################################################################
####################                USER PLAYER SESSION ABOVE                  ##########################
#########################################################################################################

@app.route("/city/start",methods=['GET',"POST"])
def start_city():
    if 'logged_in' in session:
        form=StartCityForm()
        msg=''
        if form.validate_on_submit():
            cityName=form.cityName.data

            data={
                "cityName":cityName,
                "player_id":session['player_id']
            }
            response=requests.post("http://localhost:8080/city/create/",json=data)
            if response.status_code == 200:
                return redirect(url_for('main'))
            else:
                msg='Nomde de cidade indisponível'
        return render_template("create_city.html",msg=msg,form=form)
    else:return redirect(url_for('login'))

@app.route("/city/barracks/",methods=['GET','POST'])
def recruit_troops():
    if not 'logged_in' in session:
        return redirect(url_for('login'))
    else:
        form=RecruitForm()
        if form.validate_on_submit():
            player_response = requests.get(f"http://localhost:8080/player/info/{session['player_id']}")
            response = requests.post("http://localhost:8080/mob/new/",json=player_response.json())
            return render_template("mob_profile.html",mob=response.json())
        return render_template("city_barracks.html",form=form)


#########################################################################################################
####################                CITY SESSION ABOVE                  #################################
#########################################################################################################

@app.route("/player/army/",methods=["GET"])
def see_army():
    if not 'logged_in'in session:
        return redirect(url_for("login"))
    else:
        player_response=requests.get(f"http://localhost:8080/player/info/{session['player_id']}")
        response = requests.get("http://localhost:8080/mob/army/",json=player_response.json())
        return render_template("player_army.html",army=response.json())

@app.route("/player/mob/profile<mob>/",methods=['GET'])
def mob_profile(mob):

    mob = requests.get(f"http://localhost:8080/mob/profile/",json={"mob_id":mob,"player_id":session["player_id"]})
    return render_template("mob_profile.html",obj=mob)


if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)