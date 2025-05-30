from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

instance_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
os.makedirs(instance_dir, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(instance_dir, 'app.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

user_project = db.Table('user_project',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'))
)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    users = db.relationship('User', secondary=user_project, back_populates='projects')
    sprints = db.relationship('Sprint', backref='project', lazy=True)
    tasks = db.relationship('Task', backref='project', lazy=True)

class Sprint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    tasks = db.relationship('Task', backref='sprint', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    tasks = db.relationship('Task', backref='user', lazy=True, foreign_keys='Task.user_id')
    assigned_tasks = db.relationship('Task', backref='assignee', lazy=True, foreign_keys='Task.assignee_id')
    projects = db.relationship('Project', secondary=user_project, back_populates='users')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Open')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    sprint_id = db.Column(db.Integer, db.ForeignKey('sprint.id'), nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    story_points = db.Column(db.Integer, nullable=True)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        user = User(username=username, password=hashed_pw, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login') )

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    if session.get('role') != 'admin':
        flash('Only admin can delete projects.', 'danger')
        return redirect(url_for('manage_projects'))
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted!', 'info')
    return redirect(url_for('manage_projects'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    projects = user.projects if session.get('role') != 'admin' else Project.query.all()
    selected_project_id = request.args.get('project', type=int)
    selected_sprint_id = request.args.get('sprint', type=int)
    selected_project = None
    selected_sprint = None
    tasks = []
    sprints = []
    all_project_tasks = []
    if selected_project_id:
        selected_project = Project.query.get(selected_project_id)
        sprints = Sprint.query.filter_by(project_id=selected_project_id).all()
        all_project_tasks = Task.query.filter_by(project_id=selected_project_id).all()
        if selected_sprint_id:
            selected_sprint = Sprint.query.get(selected_sprint_id)
            tasks = Task.query.filter_by(project_id=selected_project_id, sprint_id=selected_sprint_id).all()
        else:
            tasks = all_project_tasks
    users = User.query.all()
    return render_template('dashboard.html', 
        projects=projects, 
        selected_project=selected_project, 
        sprints=sprints, 
        selected_sprint=selected_sprint, 
        tasks=tasks, 
        all_project_tasks=all_project_tasks,
        role=session.get('role'),
        users=users
    )

@app.route('/projects', methods=['GET', 'POST'])
@login_required
def manage_projects():
    if request.method == 'POST':
        if session.get('role') != 'admin':
            flash('Only admins can create projects.', 'danger')
            return redirect(url_for('manage_projects'))
        name = request.form['name']
        description = request.form['description']
        if not name:
            flash('Project name required.', 'danger')
        elif Project.query.filter_by(name=name).first():
            flash('Project already exists.', 'danger')
        else:
            project = Project(name=name, description=description)
            db.session.add(project)
            db.session.commit()
            user = User.query.get(session['user_id'])
            project.users.append(user)
            db.session.commit()
            flash('Project created and you have been assigned to it.', 'success')
    projects = Project.query.all()
    users = User.query.all()
    user = User.query.get(session['user_id'])
    return render_template('projects.html', projects=projects, users=users, user=user, role=session.get('role'))

@app.route('/projects/<int:project_id>/assign', methods=['POST'])
@login_required
def assign_users_to_project(project_id):
    project = Project.query.get_or_404(project_id)
    if session.get('role') == 'admin':
        user_ids = request.form.getlist('user_ids')
        project.users = User.query.filter(User.id.in_(user_ids)).all()
        db.session.commit()
        flash('Users updated for project.', 'success')
    else:
        user = User.query.get(session['user_id'])
        if user not in project.users:
            project.users.append(user)
            db.session.commit()
            flash('You have been assigned to this project.', 'success')
        else:
            flash('You are already assigned to this project.', 'info')
    return redirect(url_for('manage_projects'))

@app.route('/projects/<int:project_id>/sprints', methods=['POST'])
@login_required
def add_sprint(project_id):
    if session.get('role') != 'admin':
        flash('Only admins can add sprints.', 'danger')
        return redirect(url_for('manage_projects'))
    name = request.form['name']
    if not name:
        flash('Sprint name required.', 'danger')
    else:
        db.session.add(Sprint(name=name, project_id=project_id))
        db.session.commit()
        flash('Sprint added.', 'success')
    return redirect(url_for('manage_projects'))

@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    user = User.query.get(session['user_id'])
    projects = user.projects if session.get('role') != 'admin' else Project.query.all()
    users = User.query.all()
    sprints = []
    selected_project_id = request.args.get('project_id', type=int)
    selected_sprint_id = request.args.get('sprint_id', type=int)
    project_users = []
    if selected_project_id:
        sprints = Sprint.query.filter_by(project_id=selected_project_id).all()
        selected_project = next((p for p in projects if p.id == selected_project_id), None)
        if selected_project:
            project_users = selected_project.users
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        project_id = request.form.get('project_id', type=int)
        sprint_id = request.form.get('sprint_id', type=int)
        assignee_id = request.form.get('assignee_id', type=int)
        story_points = request.form.get('story_points', type=int)
        if not title or not status or not project_id or not sprint_id:
            flash('Title, status, project, and sprint are required.', 'danger')
            return redirect(url_for('create_task', project_id=project_id, sprint_id=sprint_id))
        task = Task(
            title=title, 
            description=description, 
            status=status, 
            user_id=session['user_id'],
            project_id=project_id,
            sprint_id=sprint_id,
            assignee_id=assignee_id if assignee_id else None,
            story_points=story_points if story_points else None
        )
        db.session.add(task)
        db.session.commit()
        flash('Task created!', 'success')
        return redirect(url_for('dashboard', project=project_id, sprint=sprint_id))
    return render_template('task_form.html', action='Create', projects=projects, sprints=sprints, users=users, project_users=project_users, selected_project_id=selected_project_id, selected_sprint_id=selected_sprint_id)

@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    projects = user.projects if session.get('role') != 'admin' else Project.query.all()
    sprints = Sprint.query.filter_by(project_id=task.project_id).all()
    users = User.query.all()
    if session.get('role') != 'admin' and user not in task.project.users:
        flash('Not authorized.', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        task.status = request.form['status']
        task.project_id = request.form.get('project_id', type=int)
        task.sprint_id = request.form.get('sprint_id', type=int)
        task.assignee_id = request.form.get('assignee_id', type=int)
        task.story_points = request.form.get('story_points', type=int)
        db.session.commit()
        flash('Task updated!', 'success')
        return redirect(url_for('dashboard', project=task.project_id))
    return render_template('task_form.html', action='Edit', task=task, projects=projects, sprints=sprints, users=users)

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    if session.get('role') != 'admin' and user not in task.project.users:
        return jsonify({'error': 'Not authorized'}), 403
    db.session.delete(task)
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True})
    flash('Task deleted!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/tasks/<int:task_id>/move', methods=['POST'])
@login_required
def move_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    if session.get('role') != 'admin' and user not in task.project.users:
        return jsonify({'error': 'Not authorized'}), 403
    data = request.get_json()
    new_status = data.get('status')
    if new_status not in ['Open', 'In Progress', 'Closed']:
        return jsonify({'error': 'Invalid status'}), 400
    task.status = new_status
    db.session.commit()
    return jsonify({'success': True})

@app.before_request
def inject_sidebar_projects():
    g.projects = []
    g.selected_project = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        g.projects = user.projects if session.get('role') != 'admin' else Project.query.all()
        project_id = request.args.get('project', type=int)
        if project_id:
            g.selected_project = Project.query.get(project_id)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)