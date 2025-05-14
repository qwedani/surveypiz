from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import csv
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Модели
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    polls = db.relationship('Poll', backref='author', lazy=True)


class Poll(db.Model):
    __tablename__ = 'polls'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questions = db.relationship('Question', backref='poll', lazy=True, cascade='all, delete-orphan')


class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # text, radio, checkbox
    options = db.Column(db.String(500))
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)


class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


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
        return json.loads(data) if data else []
    except:
        return []


# Маршруты
@app.route('/')
def index():
    polls = Poll.query.all()
    return render_template('index.html', polls=polls)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        user = User(username=username)
        user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Registration successful!', 'success')
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

            for q_text, q_type, opts in zip(questions, types, options_list):
                if not q_text.strip():
                    raise ValueError("Question text cannot be empty")

                options = None
                if q_type in ['radio', 'checkbox']:
                    options = json.loads(opts)
                    if not isinstance(options, list):
                        raise ValueError("Options must be a JSON array")

                question = Question(
                    text=q_text.strip(),
                    type=q_type,
                    options=json.dumps(options, ensure_ascii=False) if options else None,
                    poll_id=poll.id
                )
                db.session.add(question)

            db.session.commit()
            flash('Poll created successfully!', 'success')
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
                response = None
                if question.type == 'checkbox':
                    response = ','.join(request.form.getlist(f'q_{question.id}'))
                else:
                    response = request.form.get(f'q_{question.id}')

                if response:
                    answer = Answer(
                        content=response,
                        question_id=question.id,
                        user_id=current_user.id if current_user.is_authenticated else None
                    )
                    db.session.add(answer)

            db.session.commit()
            flash('Thank you for participating!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')

    return render_template('poll.html', poll=poll)


@app.route('/results/<int:poll_id>')
@login_required
def poll_results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if poll.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('index'))

    return render_template('poll_results.html', poll=poll)


@app.route('/export_csv/<int:poll_id>')
@login_required
def export_csv(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    csv_buffer = BytesIO()
    writer = csv.writer(csv_buffer)

    headers = ['User', 'Timestamp'] + [q.text for q in poll.questions]
    writer.writerow(headers)

    answers_data = {}
    for answer in Answer.query.join(Question).filter(Question.poll_id == poll_id).all():
        user_key = answer.user_id or 'anonymous'
        if user_key not in answers_data:
            answers_data[user_key] = {
                'user': f"User {answer.user_id}" if answer.user_id else "Anonymous",
                'timestamp': answer.timestamp,
                'answers': {}
            }
        answers_data[user_key]['answers'][answer.question_id] = answer.content

    for data in answers_data.values():
        row = [
            data['user'],
            data['timestamp'].strftime('%Y-%m-%d %H:%M')
        ]
        for question in poll.questions:
            row.append(data['answers'].get(question.id, ''))
        writer.writerow(row)

    csv_buffer.seek(0)
    return send_file(
        csv_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"{poll.title}_results.csv"
    )


if __name__ == '__main__':
    app.run(debug=True)