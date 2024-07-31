from flask import Flask, jsonify, render_template, request, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FormField, FieldList
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config.update(
    SECRET_KEY="2@l!ITu",
    SQLALCHEMY_DATABASE_URI='postgresql://postgres:1234@localhost/Users',
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.context_processor
def inject_user():

    questions = Questions.query.order_by(Questions.question_num).all()
    question_list = {}

    for i, value in enumerate(questions, 1):
        key = f'question{i}'
        question_list[key] = value.question

    session['questions'] = question_list
    adults = session.get('adults')
    adult_first_names = session.get('adult_names')
    current_adult_answers = session.get('current_adult_answers')
    print("HER")
    print(current_adult_answers)
    
    return dict(logged_in=current_user.is_authenticated, username=current_user.username if current_user.is_authenticated else None, adults=adults, adult_names=adult_first_names, questions=question_list, string_answers=current_adult_answers)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


logged_in = False


class Users(db.Model, UserMixin):

    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(500), nullable=False, unique=True)
    password = db.Column(db.String(500), nullable=False)

    # relationships
    basic_answers = db.relationship(
        'UserAnswersBasic', backref='user', lazy=True)
    children = db.relationship('Children', backref='user', lazy=True)
    adults = db.relationship('Adults', backref='user', lazy=True)
    question_1_answers = db.relationship(
        'AnswerQuestion1', backref='user', lazy=True)
    question_2_answers = db.relationship(
        'AnswerQuestion2', backref='user', lazy=True)
    question_3_answers = db.relationship(
        'AnswerQuestion3', backref='user', lazy=True)
    question_4_answers = db.relationship(
        'AnswerQuestion4', backref='user', lazy=True)
    question_5_answers = db.relationship(
        'AnswerQuestion5', backref='user', lazy=True)
    question_6_answers = db.relationship(
        'AnswerQuestion6', backref='user', lazy=True)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return '[username: {}, password: {} ]'.format(self.username, self.password)


class UserAnswersBasic(db.Model, UserMixin):

    __tablename__ = 'UserAnswers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    num_adults = db.Column(db.Integer, nullable=False)

    def __init__(self, num_adults, user_id):
        self.num_adults = num_adults
        self.user_id = user_id


class Adults(db.Model, UserMixin):

    __tablename__ = 'Adults'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    adult_name = db.Column(db.String(80), nullable=False)

    def __init__(self, name, user_id):
        self.adult_name = name
        self.user_id = user_id

    def __repr__(self):
        return "Adult name: {}".format(self.adult_name)

class AnswerQuestion1(db.Model, UserMixin):

    __tablename__ = 'Question 1 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)
    
    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.question_num, self.current_adult, self.answer_choice)


class AnswerQuestion2(db.Model, UserMixin):

    __tablename__ = 'Question 2 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)
    
    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.answer_num, self.current_adult, self.answer_choice)


class AnswerQuestion3(db.Model, UserMixin):

    __tablename__ = 'Question 3 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)

    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.answer_num, self.current_adult, self.answer_choice)


class AnswerQuestion4(db.Model, UserMixin):

    __tablename__ = 'Question 4 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)

    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.answer_num, self.current_adult, self.answer_choice)


class AnswerQuestion5(db.Model, UserMixin):

    __tablename__ = 'Question 5 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)

    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.answer_num, self.current_adult, self.answer_choice)

class AnswerQuestion6(db.Model, UserMixin):

    __tablename__ = 'Question 6 Answers'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)

    current_adult = db.Column(db.String(50), nullable=True)

    answer_choice = db.Column(db.String(1), nullable=False)

    answer_choice_string = db.Column(db.String(200), nullable=False)

    def __init__(self, question_num, user_id, current_adult, answer_choice, answer_choice_string):
        self.question_num = question_num
        self.user_id = user_id
        self.current_adult = current_adult
        self.answer_choice = answer_choice
        self.answer_choice_string = answer_choice_string

    def __repr__(self):
        return "User id: {}, Answer Num: {}, Current Adult: {}, Answer: {}".format(self.user_id, self.answer_num, self.current_adult, self.answer_choice)

class Questions(db.Model):

    __tablename__ = 'questions'

    id = db.Column(db.Integer, primary_key=True)

    question_num = db.Column(db.Integer, nullable=False)

    question = db.Column(db.String(255), nullable=False)

    def __init__(self, question):
        self.quesiton = question

    def __repr__(self):
        return "Question: {}".format(self.quesiton)

class BasicInformationForm(FlaskForm):

    num_adults = IntegerField(validators=[InputRequired()], render_kw={
                              "placeholder": "Number of Adults (e.g 2)", "class": "form-control"})
    submit = SubmitField("Next")

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = Users.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one."
            )

class LoginForm(FlaskForm):

    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                print("CURRENT USER: ")
                print(current_user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/resgister', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            'utf-8')  # store as valid string using decode utf-8
        new_user = Users(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    
    question_1_answers = {"A": "Saver", "B": "Spender", "C": "Investor", "D": "Risk-Taker", "E": "Cautious"}
    question_2_answers = {"A": "Save It", "B": "Invest It", "C": "Pay off Debt", "D": "Splurge On Something", "E": "Donate It"}
    question_3_answers = {"A": "Buying a Home", "B": "Paying off Debt", "C": "Save for Education", "D": "Retirement", "E": "Other"}   
    question_4_answers = {"A": "40", "B": "50", "C": "60", "D": "Never Thought About it", "E": "Other"}
    question_5_answers = {"A": "Very Comortable", "B": "Somewhat Comfortable", "C": "Comfortable", "D": "Not Comfortable At All", "E": "Leave it to the Professionals"}
    question_6_answers = {"A": "High", "B": "Medium", "C": "Low Risk", "D": "No Risk"}
    
    current_adult_answers = {}
    
    first_names = session.get('adult_names')
    
    if request.is_json:
        data = request.get_json()
        
        for item in data:
        # Each item is a dictionary with a single key-value pair
            for name, data in item.items():
                # Now you can access the values
                question_number = data['question_number']
                adult_answer = data['adult_answer']
                answer = eval(f'question_{question_number}_answers')[f'{adult_answer}']
                print("ANSWER")
                print(answer)
                
                if name not in current_adult_answers:
                    
                    current_adult_answers[name] = []
                
                print("CURRENT ADULT Before ADD")
                print(current_adult_answers)
                
                current_adult_answers[name].append([question_number, answer])
            session['current_adult_answers'] = current_adult_answers

    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    global logged_in
    logged_in = False
    return redirect(url_for('home'))


@app.route('/questionaire', methods=['GET', 'POST'])
def questionaire():
    basic_form = BasicInformationForm()
    if basic_form.validate_on_submit():
        answers = UserAnswersBasic(basic_form.num_adults.data, current_user.id)
        db.session.add(answers)
        db.session.commit()
        session['adults'] = basic_form.num_adults.data
        session['form_data'] = request.form  # Store form data in session
        return redirect(url_for('questionaire2'))
    return render_template('questionaire.html', basic_form=basic_form)


@app.route('/questionaire2', methods=['GET', 'POST'])
def questionaire2():
    adult_names = {}
    if request.is_json:
        json_data = request.get_json()
        print(json_data)
        for i in range(int(session['adults'])):
            adult_names[f'adult{i + 1}'] = json_data.get(f'adult{i}')
            data = Adults(adult_names[f'adult{i + 1}'], current_user.id)
            db.session.add(data)
        db.session.commit()

    session['adult_names'] = adult_names    
        
    form_data = session.get('form_data')  # Get form data from session
    return render_template('questionaire2.html', form_data=form_data)


@app.route('/questionaire3', methods=['GET', 'POST'])
def questionaire3():
    
    question_1_answers = {"A": "Saver", "B": "Spender", "C": "Investor", "D": "Risk-Taker", "E": "Cautious"}
    question_2_answers = {"A": "Save It", "B": "Invest It", "C": "Pay off Debt", "D": "Splurge On Something", "E": "Donate It"}
    question_3_answers = {"A": "Buying a Home", "B": "Paying off Debt", "C": "Save for Education", "D": "Retirement", "E": "Other"}   
    question_4_answers = {"A": "40", "B": "50", "C": "60", "D": "Never Thought About it", "E": "Other"}
    question_5_answers = {"A": "Very Comortable", "B": "Somewhat Comfortable", "C": "Comfortable", "D": "Not Comfortable At All", "E": "Leave it to the Professionals"}
    question_6_answers = {"A": "High", "B": "Medium", "C": "Low Risk", "D": "No Risk"}
    
    
    if request.is_json:
        data = request.get_json()
        question_number = data.get('question_number')
        answer_choice = data.get('adult_answer')
        current_adult = data.get('current_adult')
        
        print(current_adult)
        if question_number == 1:
            save = AnswerQuestion1(question_number,current_user.id, current_adult, answer_choice, question_1_answers[f'{answer_choice}'])
        elif question_number == 2:
            save = AnswerQuestion2(question_number,current_user.id, current_adult, answer_choice, question_2_answers[f'{answer_choice}'])
        elif question_number == 3:
            save = AnswerQuestion3(question_number,current_user.id, current_adult, answer_choice, question_3_answers[f'{answer_choice}'])
            
        elif question_number == 4:
            save = AnswerQuestion4(question_number,current_user.id, current_adult, answer_choice, question_4_answers[f'{answer_choice}'])
            
        elif question_number == 5:
            save = AnswerQuestion5(question_number,current_user.id, current_adult, answer_choice, question_5_answers[f'{answer_choice}'])
            
        elif question_number == 6:
            save = AnswerQuestion6(question_number,current_user.id, current_adult, answer_choice, question_6_answers[f'{answer_choice}'])

        db.session.add(save)
        db.session.commit()

    # Pass form_data to the template
    return render_template('questionaire3.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
