import pymysql
pymysql.install_as_MySQLdb()  # Используем pymysql в качестве MySQLdb
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import requests
import math

# Инициализация приложения Flask
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Устанавливаем секретный ключ для сессий

# Настройка базы данных MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/your_database'  # Подключение к БД
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Отключаем слежение за изменениями для повышения производительности

# Инициализация расширений Flask
db = SQLAlchemy(app)  # Инициализация базы данных
bcrypt = Bcrypt(app)  # Для хеширования паролей
login_manager = LoginManager()  # Инициализация менеджера входа
login_manager.init_app(app)
login_manager.login_view = 'login'  # Переход на страницу входа, если пользователь не авторизован

# Модель пользователя для БД
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Флаг для обозначения пользователя как администратора

# Главная страница (требует входа)
@app.route('/')
@login_required
def home():
    # Значения по умолчанию для пагинации
    page = 1
    total_pages = 1
    data = []  # Пустой список данных, если нет данных
    return render_template('index.html', page=page, total_pages=total_pages, data=data)

# Функция загрузки пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Возвращает пользователя по его ID

# Регистрация нового пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Хеширование пароля
        ip_address = request.remote_addr  # Получение IP-адреса пользователя

        # Проверка на наличие существующего пользователя
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует.')
            return redirect(url_for('register'))

        # Создание нового пользователя
        new_user = User(username=username, password=hashed_password, ip_address=ip_address)
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно!')
        return redirect(url_for('login'))

    return render_template('register.html')

from urllib.parse import urlparse, urljoin

# Проверка безопасности URL (не ведет ли на внешний ресурс)
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Вход пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()  # Ищем пользователя по имени

        if user and bcrypt.check_password_hash(user.password, password):  # Проверка пароля
            login_user(user)  # Авторизация пользователя
            print(f"User {user.username} успешно вошел в систему")
            print(f"Current user is_authenticated: {current_user.is_authenticated}")

            # Перенаправление пользователя на следующую страницу после авторизации
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            else:
                return redirect(url_for('flight_data'))  # Перенаправление на flights
        else:
            flash('Неверное имя пользователя или пароль')
            return redirect(url_for('login'))

    return render_template('login.html')

# Выход пользователя
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Завершаем сессию пользователя
    session.clear()  # Очищаем сессию
    return redirect(url_for('login'))

# Страница отображения данных о полетах
@app.route('/flights')
@login_required
def flight_data():
    # Получаем параметры для фильтрации и пагинации
    page = request.args.get('page', 1, type=int)
    per_page = 10
    callsign = request.args.get('callsign')
    origin_country = request.args.get('origin_country')
    flight_number = request.args.get('flight_number')
    latitude = request.args.get('latitude')
    longitude = request.args.get('longitude')

    # URL для сохранения фильтров при переходе по страницам
    base_url = url_for('flight_data', callsign=callsign, origin_country=origin_country,
                       flight_number=flight_number, latitude=latitude, longitude=longitude)

    # Запрос данных о полетах через API OpenSky Network
    url = 'https://opensky-network.org/api/states/all'
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json().get('states', [])

        # Применяем фильтры
        if callsign:
            data = [plane for plane in data if callsign.lower() in plane[1].lower()]
        elif origin_country:
            data = [plane for plane in data if origin_country.lower() in plane[2].lower()]
        elif flight_number:
            data = [plane for plane in data if flight_number.lower() in plane[1].lower()]
        elif latitude and longitude:
            latitude = float(latitude)
            longitude = float(longitude)
            data = [plane for plane in data if
                    plane[6] and plane[5] and abs(plane[6] - latitude) < 1 and abs(plane[5] - longitude) < 1]

        total_planes = len(data)
        total_pages = math.ceil(total_planes / per_page)  # Рассчитываем количество страниц

        # Пагинация
        data = data[(page - 1) * per_page:page * per_page]
    else:
        data = []
        total_pages = 1

    return render_template('index.html', data=data, page=page, total_pages=total_pages,
                           callsign=callsign, origin_country=origin_country,
                           flight_number=flight_number, latitude=latitude, longitude=longitude, base_url=base_url)

# Обработка поиска по позывному
@app.route('/search_by_callsign', methods=['POST'])
@login_required
def search_by_callsign():
    callsign = request.form.get('callsign')
    return redirect(url_for('flight_data', callsign=callsign))

# Обработка поиска по стране происхождения
@app.route('/search_by_country', methods=['POST'])
@login_required
def search_by_country():
    origin_country = request.form.get('origin_country')
    return redirect(url_for('flight_data', origin_country=origin_country))

# Обработка поиска по номеру рейса
@app.route('/search_by_flight', methods=['POST'])
@login_required
def search_by_flight():
    flight_number = request.form.get('flight_number')
    return redirect(url_for('flight_data', flight_number=flight_number))

# Обработка поиска по координатам
@app.route('/search_by_coordinates', methods=['POST'])
@login_required
def search_by_coordinates():
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    return redirect(url_for('flight_data', latitude=latitude, longitude=longitude))

# Модель для хранения избранных самолётов
class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    callsign = db.Column(db.String(10), nullable=False)

    user = db.relationship('User', backref='favorites')  # Связь с моделью пользователя

# Добавление самолета в избранное
@app.route('/add_to_favorites', methods=['POST'])
@login_required
def add_to_favorites():
    callsign = request.json.get('callsign')
    # Проверяем, есть ли уже этот самолёт в избранном
    if not Favorite.query.filter_by(user_id=current_user.id, callsign=callsign).first():
        favorite = Favorite(user_id=current_user.id, callsign=callsign)
        db.session.add(favorite)
        db.session.commit()
        return jsonify({"message": f"{callsign} добавлен в избранное"})
    else:
        return jsonify({"message": f"{callsign} уже в избранном"})

# Страница избранных самолётов
@app.route('/favorites')
@login_required
def favorites():
    # Извлекаем избранные рейсы для текущего пользователя
    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    callsigns = [fav.callsign for fav in favorites]

    # Получаем информацию о самолётах по их позывным
    url = 'https://opensky-network.org/api/states/all'
    response = requests.get(url)
    if response.status_code == 200:
        data = [plane for plane in response.json().get('states', []) if plane[1] in callsigns]
    else:
        data = []
    return render_template('favorites.html', data=data)

# Удаление самолета из избранного
@app.route('/remove_from_favorites', methods=['POST'])
@login_required
def remove_from_favorites():
    callsign = request.json.get('callsign')
    favorite = Favorite.query.filter_by(user_id=current_user.id, callsign=callsign).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({"message": f"{callsign} удалён из избранного"})
    return jsonify({"message": f"{callsign} не найден в избранном"})

# Админ-панель
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:  # Проверка на наличие прав администратора
        return "Доступ запрещён", 403
    users = User.query.all()  # Получаем всех пользователей для админ-панели
    return render_template('admin.html', users=users)

# Удаление пользователя через админ-панель
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.username != 'admin':  # Проверяем, является ли текущий пользователь админом
        return "Доступ запрещён", 403

    user = User.query.get(user_id)  # Находим пользователя по ID
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.username} был удалён.')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создание всех таблиц в базе данных при запуске
    app.run(debug=True)  # Запуск приложения