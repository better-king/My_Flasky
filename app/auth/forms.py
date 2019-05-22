from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import DataRequired,Length,Email,Regexp,EqualTo
from wtforms import ValidationError
from ..models import User

class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Length(1,64),Email()])
    username = StringField('Username',validators=[DataRequired(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Username must have only letters,numbers,dots or underscores')])
    password = PasswordField('Password',validators=[DataRequired(),EqualTo('password2',message='Passwords must match.')])
    password2 = PasswordField('Confirm Password',validators=[DataRequired()])
    sumbit = SubmitField('Register')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def vaildate_username(self,field):
        if User.query.filter_by(username = field.data).first():
            raise ValidationError('Username already in use.')

#修改密码
class ChangePassWordForm(FlaskForm):
    old_password = PasswordField('Old Password',validators=[DataRequired()])
    new_password = PasswordField('New Password',validators=[DataRequired(),EqualTo('new_password2',message='Passwords must match.')])
    new_password2 = PasswordField('Confirm New Password',validators=[DataRequired()])
    sumbit = SubmitField('Confirm to change password')

#忘记密码
class ForgotPasswordForm(FlaskForm):
    email = StringField('Enter the email address you registered at the time of registration',validators=[DataRequired(),Length(1,64),Email()])
    sumbit = SubmitField('Confirm')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password',validators=[DataRequired(), EqualTo('new_password2', message='Passwords must match.')])
    new_password2 = PasswordField('Confirm New Password', validators=[DataRequired()])
    sumbit = SubmitField('Confirm to reset password')