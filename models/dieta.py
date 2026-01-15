from database import db
#from flask_login import UserMixin

class Dieta(db.Model):
    # ID (int), username (text), password (text)
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False, unique=True)
    descricao = db.Column(db.String(80), nullable=False)
    data_hora = db.Column(db.DateTime, nullable=False)
    dieta = db.Column(db.Boolean, nullable=False, default=True)