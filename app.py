from flask import Flask, render_template, url_for, redirect, request,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # Make sure to use three slashes here
app.config["SECRET_KEY"] = "thisisasecretkey"
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

db = SQLAlchemy(app)
app.app_context().push()

# Correctly define the User model
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
        content = request.form['content']  # Get the content from a form
        new_secret = Secret(content=content, user_id=current_user.id)  # Create a new secret
        db.session.add(new_secret)  # Add it to the session
        db.session.commit()  # Commit the session to save the secret to the database
        return redirect(url_for('dashboard'))  # Redirect to the dashboard

    return render_template("add_secret.html")  # Render the form to add a secret

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/dashboard", methods=['GET'])
@login_required
def dashboard():
    secrets = Secret.query.filter_by(user_id=current_user.id).all()  # Get secrets for the logged-in user
    return render_template("dashboard.html", username=current_user.username, secrets=secrets)

@app.route("/login", methods=['GET', 'POST'])


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
                flash("Incorrect password. Please try again.", "danger")  # Flash message for incorrect password
        else:
            flash("Username does not exist. Please try again.", "danger")  # Flash message for non-existent username

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

@app.route("/logout", methods=["GET", "POST"])  # Corrected 'methods'
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/delete_secret/<int:secret_id>")
@login_required
def delete_secret(secret_id):
    secret_to_delete = Secret.query.get_or_404(secret_id)
    if secret_to_delete.user_id == current_user.id:  # Ensure that the secret belongs to the current user
        db.session.delete(secret_to_delete)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/edit_secret/<int:secret_id>", methods=['GET', 'POST'])
@login_required
def edit_secret(secret_id):
    secret = Secret.query.get_or_404(secret_id)  # Fetch the secret by ID

    if request.method == 'POST':
        secret.content = request.form['content']  # Update the content
        db.session.commit()  # Commit the changes to the database
        return redirect(url_for('dashboard'))  # Redirect to the dashboard

    return render_template("edit_secret.html", secret=secret)  # Render the edit form

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    # Remove all secrets belonging to the current user
    secrets_to_delete = Secret.query.filter_by(user_id=current_user.id).all()
    for secret in secrets_to_delete:
        db.session.delete(secret)  # Delete each secret

    # Now remove the user from the database
    db.session.delete(current_user)  # Delete the current user
    db.session.commit()  # Commit all deletions to the database
    logout_user()  # Log out the user after deletion
    return redirect(url_for('home'))  # Redirect to the home page

if __name__ == "__main__":
    app.run(debug=True)
