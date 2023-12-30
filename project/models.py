from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class Employee(db.Model):
    E_ID = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    E_UserID = db.Column(db.String(100), unique=True)
    E_Name = db.Column(db.String(100))
    E_Department = db.Column(db.String(100))
    E_Password = db.Column(db.String(100))
    E_Salary = db.Column(db.String(100))
    E_TC = db.Column(db.String(100))