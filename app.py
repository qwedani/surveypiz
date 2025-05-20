from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from flask_migrate import Migrate
from datetime import datetime
from openpyxl import Workbook
from io import BytesIO,StringIO
import json
import csv


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)

migrate = Migrate(app, db)

# Модели
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    polls = db.relationship('Poll', backref='author', lazy=True)
    answers = db.relationship('Answer', backref='user', lazy=True)

class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    order = db.Column(db.String, nullable=True)  # Столбец для хранения порядка вопросов в формате JSON
    questions = db.relationship('Question', backref='poll', lazy=True, cascade='all, delete-orphan')
    answers = db.relationship('Answer', backref='poll', lazy=True, cascade='all, delete-orphan')

    @property
    def order_list(self):
        return json.loads(self.order) if self.order else []

    @order_list.setter
    def order_list(self, value):
        self.order = json.dumps(value)

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'text', 'radio', 'checkbox'
    options = db.Column(db.String(500))
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False, index=True)
    answers = db.relationship('Answer', backref='question', lazy=True, cascade="all, delete-orphan")

    @property
    def options_list(self):
        try:
            return json.loads(self.options) if self.options else []
        except json.JSONDecodeError:
            return []

    @options_list.setter
    def options_list(self, value):
        if not isinstance(value, list):
            raise ValueError("Options must be a list")
        self.options = json.dumps(value, ensure_ascii=False)

class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False, index=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

def set_poll_id(mapper, connection, target):
    if target.poll_id is None and target.question_id:
        question = db.session.get(Question, target.question_id)
        if question:
            target.poll_id = question.poll_id

# Инициализация БД
with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Фильтр для шаблонов
@app.template_filter('from_json')
def from_json_filter(data):
    try:
        return json.loads(data)
    except:
        return []


# Маршруты
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Количество опросов на странице
    search_query = request.args.get('search', '').strip()  # Получаем параметр поиска

    if search_query:
        pagination = Poll.query.filter(
            (Poll.title.ilike(f'%{search_query}%')) | (Poll.author.has(User.username.ilike(f'%{search_query}%')))
        ).order_by(Poll.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        pagination = Poll.query.order_by(Poll.id.desc()).paginate(page=page, per_page=per_page, error_out=False)

    polls = pagination.items
    return render_template('index.html', polls=polls, pagination=pagination, current_user=current_user, search_query=search_query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именнем уже зарегистрирован')
            return redirect(url_for('register'))

        user = User(username=username)
        user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Вы успешно зарегистрированны!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/create_poll', methods=['GET', 'POST'])
@login_required
def create_poll():
    if request.method == 'POST':
        try:
            poll = Poll(
                title=request.form['title'],
                user_id=current_user.id
            )
            db.session.add(poll)
            db.session.flush()

            questions = request.form.getlist('question[]')
            types = request.form.getlist('type[]')
            options_list = request.form.getlist('options[]')
            order = request.form.getlist('order[]')  # Получение порядка вопросов из формы
            created_questions = []

            for q_text, q_type, opts in zip(questions, types, options_list):
                if not q_text.strip():
                    raise ValueError("Текст вопроса не может быть пуст")

                options = None
                if q_type in ['radio', 'checkbox']:
                    if opts:  # Проверяем, что opts не пустой
                        options = json.loads(opts)
                        if not isinstance(options, list):
                            raise ValueError("Некорректный формат вариантов ответа")
                    else:
                        options = []  # Если opts пустой, устанавливаем пустой список

                question = Question(
                    text=q_text.strip(),
                    type=q_type,
                    options=json.dumps(options, ensure_ascii=False) if options else None,
                    poll_id=poll.id
                )
                db.session.add(question)
                created_questions.append(question)

            # Присваивание ID новым вопросам и установка порядка
            db.session.flush()
            poll.order_list = [str(q.id) for q in created_questions]  # Сохраняем порядок по умолчанию
            if order and order[0]:  # Если порядок передан из формы
                poll.order_list = json.loads(order[0])

            db.session.commit()
            flash('Опрос успешно создан!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')

    return render_template('create_poll.html')


@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def view_poll(poll_id):
    poll = Poll.query.options(db.joinedload(Poll.questions)).get_or_404(poll_id)

    if request.method == 'POST':
        try:
            for question in poll.questions:
                if question.type == 'checkbox':
                    response = ','.join(request.form.getlist(f'q_{question.id}'))
                else:
                    response = request.form.get(f'q_{question.id}')

                if response:
                    answer = Answer(
                        content=response,
                        question_id=question.id,
                        poll_id=poll.id,
                        user_id=current_user.id if current_user.is_authenticated else None
                    )
                    db.session.add(answer)

            db.session.commit()
            flash('Спасибо за участие!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')

    # Сортировка вопросов по order_list
    order_list = poll.order_list or [str(q.id) for q in poll.questions]  # Используем order_list или порядок по умолчанию
    sorted_questions = sorted(poll.questions, key=lambda q: order_list.index(str(q.id)) if str(q.id) in order_list else len(order_list))

    return render_template('poll.html', poll=poll, questions=sorted_questions)

@app.route('/my_polls')
@login_required
def my_polls():
    user_polls = Poll.query.filter_by(user_id=current_user.id).order_by(Poll.id.desc()).all()
    return render_template('my_polls.html', polls=user_polls)


@app.route('/results/<int:poll_id>')
@login_required
def poll_results(poll_id):
    poll = Poll.query.options(
        joinedload(Poll.questions),
        joinedload(Poll.answers)
    ).get_or_404(poll_id)

    if poll.user_id != current_user.id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    # Используем group_concat для агрегации ответов
    sessions = db.session.query(
        Answer.user_id,
        Answer.timestamp,
        func.group_concat(Answer.id).label('answer_ids')
    ).filter(
        Answer.poll_id == poll.id
    ).group_by(
        Answer.user_id, Answer.timestamp
    ).order_by(
        Answer.timestamp.desc()
    ).all()

    answer_sessions = []
    for session in sessions:
        user = User.query.get(session.user_id) if session.user_id else None

        # Преобразуем строку ID в список
        answer_ids = [int(id) for id in session.answer_ids.split(',')] if session.answer_ids else []

        answers = Answer.query.filter(Answer.id.in_(answer_ids)).all()

        answer_sessions.append({
            'timestamp': session.timestamp,
            'user': user,
            'answers': {answer.question_id: answer.content for answer in answers}
        })

    # Сортировка вопросов по order_list
    order_list = poll.order_list or [str(q.id) for q in poll.questions]  # Используем order_list или порядок по умолчанию
    sorted_questions = sorted(poll.questions, key=lambda q: order_list.index(str(q.id)) if str(q.id) in order_list else len(order_list))

    return render_template(
        'poll_results.html',
        poll=poll,
        questions=sorted_questions,
        answer_sessions=answer_sessions
    )


@app.route('/export_csv/<int:poll_id>')
@login_required
def export_csv(poll_id):
    poll = Poll.query.options(
        joinedload(Poll.questions)
    ).get_or_404(poll_id)

    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer, delimiter=',')

    # Заголовки
    headers = ['Время прохождения', 'Пользователь'] + [q.text for q in poll.questions]
    writer.writerow(headers)

    # Группировка ответов по сессиям (user + timestamp)
    sessions = db.session.query(
        Answer.user_id,
        Answer.timestamp,
        func.group_concat(Answer.id).label('answer_ids')
    ).filter(
        Answer.poll_id == poll.id
    ).group_by(
        Answer.user_id, Answer.timestamp
    ).order_by(
        Answer.timestamp.desc()
    ).all()

    # Сбор данных
    for session in sessions:
        # Получаем пользователя
        user = User.query.get(session.user_id) if session.user_id else None
        user_display = user.username if user else 'Anonymous'

        # Получаем ответы для сессии
        answer_ids = [int(id) for id in session.answer_ids.split(',')] if session.answer_ids else []
        answers = Answer.query.filter(Answer.id.in_(answer_ids)).all()

        # Формируем строку
        row = [
            session.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            user_display
        ]

        # Добавляем ответы в порядке вопросов
        for question in poll.questions:
            answer = next(
                (a.content for a in answers if a.question_id == question.id),
                'N/A'  # Значение по умолчанию
            )
            row.append(answer)

        writer.writerow(row)

    # Подготовка файла
    csv_buffer.seek(0)
    binary_buffer = BytesIO(csv_buffer.getvalue().encode('utf-8-sig'))

    return send_file(
        binary_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"{poll.title}_results.csv"
    )


@app.route('/export_excel/<int:poll_id>')
@login_required
def export_excel(poll_id):
    poll = Poll.query.options(
        joinedload(Poll.questions)
    ).get_or_404(poll_id)

    if poll.user_id != current_user.id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))

    # Создаем Excel-документ
    wb = Workbook()
    ws = wb.active
    ws.title = "Результаты"

    # Заголовки
    headers = ['Время прохождения', 'Пользователь'] + [q.text for q in poll.questions]
    ws.append(headers)

    # Группировка ответов по сессиям
    sessions = db.session.query(
        Answer.user_id,
        Answer.timestamp,
        func.group_concat(Answer.id).label('answer_ids')
    ).filter(
        Answer.poll_id == poll.id
    ).group_by(
        Answer.user_id, Answer.timestamp
    ).order_by(
        Answer.timestamp.desc()
    ).all()

    # Заполняем данные
    for session in sessions:
        # Получаем пользователя
        user = User.query.get(session.user_id) if session.user_id else None
        user_display = user.username if user else 'Anonymous'

        # Получаем ответы для сессии
        answer_ids = [int(id) for id in session.answer_ids.split(',')] if session.answer_ids else []
        answers = Answer.query.filter(Answer.id.in_(answer_ids)).all()

        # Формируем строку
        row = [
            session.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            user_display
        ]

        # Добавляем ответы в порядке вопросов
        for question in poll.questions:
            answer = next(
                (a.content for a in answers if a.question_id == question.id),
                'N/A'  # Значение по умолчанию
            )
            row.append(answer)

        ws.append(row)

    # Настраиваем ширину столбцов
    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            try:
                value_len = len(str(cell.value))
                if value_len > max_length:
                    max_length = value_len
            except:
                pass
        adjusted_width = (max_length + 2) * 1.2
        ws.column_dimensions[column].width = adjusted_width

    # Сохраняем в буфер
    excel_buffer = BytesIO()
    wb.save(excel_buffer)
    excel_buffer.seek(0)

    return send_file(
        excel_buffer,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f"{poll.title}_results.xlsx"
    )


@app.route('/delete_poll/<int:poll_id>', methods=['POST'])
@login_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.user_id != current_user.id:
        flash('Доступ запрещен', 'error')
        return redirect(url_for('index'))
    db.session.delete(poll)
    db.session.commit()
    flash('Опрос удален', 'success')
    return redirect(url_for('my_polls'))


@app.route('/edit_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def edit_poll(poll_id):
    # Получаем опрос или возвращаем 404, если он не существует
    poll = Poll.query.get_or_404(poll_id)

    # Проверяем, является ли текущий пользователь автором опроса
    if poll.user_id != current_user.id:
        flash('Вы не можете редактировать этот опрос.', 'danger')
        return redirect(url_for('my_polls'))

    if request.method == 'POST':
        # Обновляем название опроса
        poll.title = request.form['title']

        # Получаем данные из формы
        question_ids_form = request.form.getlist('question_id[]')  # IDs существующих вопросов
        texts = request.form.getlist('question[]')  # Тексты вопросов
        types = request.form.getlist('type[]')  # Типы вопросов
        options_list = request.form.getlist('options[]')  # Опции для вопросов
        order = json.loads(request.form.getlist('order[]')[0]) if request.form.getlist('order[]') else []  # Порядок вопросов

        # Удаляем вопросы, которые были в опросе, но отсутствуют в форме
        form_question_ids = set(question_ids_form)
        questions_to_delete = [q for q in poll.questions if str(q.id) not in form_question_ids]
        for question in questions_to_delete:
            db.session.delete(question)

        # Список для хранения порядка вопросов
        ordered_ids = []
        new_questions = []

        # Обрабатываем все вопросы из формы
        for i, text in enumerate(texts):
            # Опции для текущего вопроса
            options = None
            if types[i] in ['radio', 'checkbox']:
                opts = options_list[i]
                if opts and opts.strip():  # Проверяем, что строка не пустая
                    try:
                        options = json.loads(opts)
                        if not isinstance(options, list):
                            raise ValueError("Options must be a list")
                    except json.JSONDecodeError:
                        flash(f'Некорректный формат опций для вопроса "{text}". Опции сброшены.', 'warning')
                        options = []
                else:
                    options = []  # Если opts пустой, устанавливаем пустой список

            if i < len(question_ids_form) and question_ids_form[i]:
                # Существующий вопрос
                question_id = question_ids_form[i]
                question = Question.query.get(int(question_id))
                if question:
                    question.text = text
                    question.type = types[i]
                    question.options = json.dumps(options, ensure_ascii=False) if options else None  # Обновляем опции
                    ordered_ids.append(question_id)
            else:
                # Новый вопрос
                question = Question(
                    text=text,
                    type=types[i],
                    poll=poll,
                    options=json.dumps(options, ensure_ascii=False) if options else None
                )
                db.session.add(question)
                new_questions.append(question)

        # Присваиваем ID новым вопросам
        db.session.flush()

        # Формируем окончательный порядок
        final_order = []
        new_question_index = 0
        for item in order:
            if item.startswith("new_"):
                # Заменяем временные идентификаторы на реальные ID новых вопросов
                if new_question_index < len(new_questions):
                    final_order.append(str(new_questions[new_question_index].id))
                    new_question_index += 1
            else:
                final_order.append(item)

        # Если порядок не передан, используем порядок по умолчанию
        if not final_order:
            final_order = ordered_ids + [str(q.id) for q in new_questions]

        # Сохраняем порядок вопросов
        poll.order_list = final_order

        # Сохраняем изменения в базе данных
        db.session.commit()
        flash('Опрос успешно обновлён.', 'success')
        return redirect(url_for('my_polls'))

    # Для GET-запроса: отображаем форму редактирования
    order_list = poll.order_list or [str(q.id) for q in poll.questions]  # Используем order_list или порядок по умолчанию
    questions = sorted(poll.questions, key=lambda q: order_list.index(str(q.id)) if str(q.id) in order_list else len(order_list))
    return render_template('edit_poll.html', poll=poll, questions=questions)

if __name__ == '__main__':
    app.run(debug=True)
