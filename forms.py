from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, Form, SubmitField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Length, EqualTo
from email_validator import validate_email, EmailNotValidError

class RegistrationForm(FlaskForm):
    
    first_name = StringField('First Name:', validators=[DataRequired(message='Input First_name')])
    last_name = StringField('Last Name:', validators=[DataRequired(message='Input')])
    username = StringField('Username:', validators=[DataRequired(message="Username Required")])
    PhoneNo = StringField('Phone Number', validators=[DataRequired()])
     
    email = StringField('Email Address:', [validators.DataRequired(), validators.Email('Invalid Email address')])
    password = PasswordField('New Password:', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message=('Passwords must match'))
    ])
    confirm = PasswordField('Repeat Passwrod')
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png', 'gif', 'jpeg'], "Image only please"), validators.DataRequired()] )

class LoginForm(FlaskForm):
    username = StringField('Username:', validators=[DataRequired(message="Username Required")])
    password = PasswordField('Password:', validators=[DataRequired(message="Password Required")])

class MessageForm(FlaskForm):
    content = StringField('Content')
    submit = SubmitField('Send')

class RoomForm(FlaskForm):
    name = StringField('Name')
    description = StringField('Description')

