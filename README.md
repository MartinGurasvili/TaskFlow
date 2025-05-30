# TaskFlow

TaskFlow is a simple, Jira-like task management application built with Flask. It helps teams organize, track, and manage their work efficiently. This project uses [Poetry](https://python-poetry.org/) for dependency management and environment isolation, ensuring reproducible builds and easy setup.

![image](https://github.com/user-attachments/assets/70d7ac57-9b07-45f9-91a5-833fd14da7d5)

---

## **Features**

- Create, update, and manage tasks
- User-friendly web interface
- Lightweight and easy to deploy
- Built with Python and Flask

---

## **Getting Started**

### **Prerequisites**

- Python 3.8+
- [Poetry](https://python-poetry.org/docs/#installation) installed

---

### **Installation**

1. **Clone the repository**

```bash
git clone https://github.com/MartinGurasvili/TaskFlow.git
cd TaskFlow
```

2. **Install dependencies with Poetry**

```bash
poetry install
```

This will create a virtual environment and install all dependencies as specified in `pyproject.toml` and `poetry.lock`

---

### **Running the Application**

You can run the Flask application using Poetry to ensure it uses the managed virtual environment:

```bash
poetry run python app.py
```

By default, the app will be available at [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

### **Development Workflow**

- To activate the Poetry shell (optional):

```bash
poetry shell
```

Then run:

```bash
python app.py
```

- To add new dependencies:

```bash
poetry add <package-name>
```


---

## **Configuration**

- All app configuration can be set in `app.py` or via environment variables.
- For production, use a WSGI server such as unicorn instead of the Flask development server.

---
