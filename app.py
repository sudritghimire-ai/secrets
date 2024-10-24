from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://database_e27p_user:your_password@dpg-csd2pljv2p9s73fr2f90-a:5432/database_e27p"

app.config["SECRET_KEY"] = "thisisasecretkey"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)
app.app_context().push()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Username"}
    )
    
    password = PasswordField(
        'Password',
        validators=[InputRequired(), Length(min=4, max=20)],
        render_kw={"placeholder": "Password"}
    )
    
    submit = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        if existing_user_name:
            raise ValidationError("The username already exists.")

class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[InputRequired(), Length(min=4, max=100)],
        render_kw={"placeholder": "Username"}
    )
    
    password = PasswordField(
        'Password',
        validators=[InputRequired(), Length(min=4, max=100)],
        render_kw={"placeholder": "Password"}
    )    
    
    submit = SubmitField("Log In")

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route("/add_secret", methods=['GET', 'POST'])
@login_required
def add_secret():
    if request.method == 'POST':
        content = request.form['content']
        new_secret = Secret(content=content, user_id=current_user.id)
        db.session.add(new_secret)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template("add_secret.html")

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
    secrets = Secret.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", username=current_user.username, secrets=secrets)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.password == form.password.data:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password. Please try again.", "danger")
        else:
            flash("Username does not exist. Please try again.", "danger")

    return render_template("login.html", form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        password = form.password.data
        new_user = User(username=form.username.data, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/delete_secret/<int:secret_id>")
@login_required
def delete_secret(secret_id):
    secret_to_delete = Secret.query.get_or_404(secret_id)
    if secret_to_delete.user_id == current_user.id:
        db.session.delete(secret_to_delete)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/edit_secret/<int:secret_id>", methods=['GET', 'POST'])
@login_required
def edit_secret(secret_id):
    secret = Secret.query.get_or_404(secret_id)

    if request.method == 'POST':
        secret.content = request.form['content']
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template("edit_secret.html", secret=secret)

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    secrets_to_delete = Secret.query.filter_by(user_id=current_user.id).all()
    for secret in secrets_to_delete:
        db.session.delete(secret)

    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
