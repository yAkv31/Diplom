import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, UnidentifiedImageError
import pytesseract
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class UserQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('queries', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

pytesseract.pytesseract.tesseract_cmd = r'E:\Tesseract OCR\tesseract.exe'

smtp_server = 'smtp.mail.ru'
smtp_port = 587
sender_email = 'amir-shakirov-2002@mail.ru'
sender_password = 'NT6kLDXLdx7RjeuH8jsc'

def send_email(recipient_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, recipient_email, msg.as_string())
    server.quit()

@app.route('/')
def index():
    return render_template('index.html', user=current_user)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return render_template('index.html', message='Файл не найден', user=current_user)
    
    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', message='Файл не выбран', user=current_user)
    
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff']:
        return render_template('index.html', message='Неподдерживаемый формат файла', user=current_user)
    
    try:
        image = Image.open(file)
        text = pytesseract.image_to_string(image, lang='rus')
    except UnidentifiedImageError:
        return render_template('index.html', message='Неподдерживаемый формат файла', user=current_user)
    
    if current_user.is_authenticated:
        user_query = UserQuery(user_id=current_user.id, text=text)
        db.session.add(user_query)
        db.session.commit()
    
    return render_template('index.html', message='Распознанный текст:', text=text, user=current_user)

@app.route('/clear', methods=['POST'])
def clear_text():
    return render_template('index.html', text="", user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password == confirm_password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Аккаунт успешно создан', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пароли не совпадают', 'danger')
    return render_template('register.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Неудачный вход. Пожалуйста, проверьте email и пароль', 'danger')
    return render_template('login.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form.get('username')
        if new_username:
            current_user.username = new_username
            db.session.commit()
            flash('Имя пользователя успешно обновлено', 'success')
        else:
            flash('Имя пользователя не может быть пустым', 'danger')

    user_queries = UserQuery.query.filter_by(user_id=current_user.id).order_by(UserQuery.id.desc()).limit(5).all()
    return render_template('profile.html', queries=user_queries, user=current_user)

@app.route('/subscribe', methods=['POST'])
def subscribe():
    name = request.form.get('name')
    email = request.form.get('email')
    
    if name and email:
        subject = "Спасибо за подписку на новостную рассылку"
        body = f"Привет, {name}!\n\nСпасибо за подписку на нашу новостную рассылку."
        
        send_email(email, subject, body)
        
        return render_template('index.html', message='Вы успешно подписались на новостную рассылку!')
    else:
        return render_template('index.html', message='Пожалуйста, введите имя и электронный адрес.')
    
if __name__ == '__main__':
    app.run(debug=True)
