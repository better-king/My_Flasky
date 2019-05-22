from flask import render_template,redirect,request,url_for,flash
from flask_login import login_user
from . import auth
from ..models import User,db
from .forms import LoginForm,RegistrationForm,ChangePassWordForm,ForgotPasswordForm,ResetPasswordForm
from flask_login import logout_user,login_required,current_user
from ..email import send_email


@auth.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next =url_for('main.index')
            return redirect(next)
        flash('Invalid username or password.')
    return render_template('auth/login.html',form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email,'Confirm Your Account','auth/email/confirm',user=user,token=token)
        flash('A confirmation email hs been send to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html',form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main_index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('You have confirmation your account.Thanks')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated \
            and not current_user.confirmed \
            and request.blueprint != "auth" \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/uncofirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return  render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email,'Confirm Your Account','auth/email/confirm',user=current_user,token=token)
    flash('A new confirmation has been sent to you by email.')
    return redirect(url_for('main.index'))

#修改密码
@auth.route('/ChangePassWord',methods=['GET','POST'])
@login_required
def change_Password():
    form = ChangePassWordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.new_password.data
            db.session.add(current_user)
            db.session.commit()
            flash("你的密码已更新")
            return redirect(url_for('main.index'))
    return render_template('auth/change_password.html', form=form)

#找回密码
@auth.route('/ForgotPassWord',methods=['GET','POST'])
def forgot_Password():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ForgotPasswordForm()
    user = User.query.filter_by(email=form.email.data).first()
    if form.validate_on_submit():
        if user is None:
            flash('This email has not been registered')
        else:
            token = user.generate_reset_token()
            send_email(user.email, 'Reset Your Password', 'auth/email/reset_password', user=user, token=token)
            flash('An email with instructions to reset your password has been sent to you.')
            return redirect(url_for('main.index'))
    return render_template('auth/forgot_Password.html', form=form)

@auth.route('/reset/<token>/<username>',methods=['GET','POST'])
def Reset_Password(token,username):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.new_password.data):
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_Password.html', form=form,username=username)