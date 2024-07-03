from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Enviar')

class SignInForm(FlaskForm):
    username = StringField('Digite o Usuário', validators=[DataRequired()])
    password1 = PasswordField('Digite a Senha', validators=[DataRequired()])
    password2 = PasswordField('Digite a senha novamente', validators=[DataRequired()])
    submit = SubmitField('Enviar')

class NewPlayer(FlaskForm):
    playerName = StringField('Nome de Jogador',validators=[DataRequired()])
    submit = SubmitField('Enviar')

class StartCityForm(FlaskForm):
    cityName = StringField("Nome da sua cidade",validators=[DataRequired()])
    submit = SubmitField("Enviar")