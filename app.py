from flask import Flask, request, jsonify
from models.user import User
from models.dieta import Dieta
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from sqlalchemy.orm import joinedload
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/daily_diet'

login_manager = LoginManager()

db.init_app(app)
login_manager.init_app(app)

#view login
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

#Precisamos criar uma rota de autentaicação de login
@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #Login
        user = User.query.filter_by(username=username).first()        

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):      
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autentitação realizada com sucesso"}), 200

    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"}), 200

@app.route('/user', methods=["POST"])
#@login_required
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    cd_dieta = data.get("cd_dieta")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt() )
        user = User(username=username, password=hashed_password, cd_dieta=cd_dieta, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"}), 200

    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return {"username": user.username}
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):    
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == 'user':
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} atualizado com sucesso!"}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404
    
@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):    
    user = User.query.get(id_user)
    if current_user.role != 'admin':
        return jsonify({"message": "Operação não permitida"}), 403
    if id_user == current_user.id:
        return jsonify({"message": "Operação não permitida"}), 403
    
    if user and id_user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {id_user} deletado com sucesso!"}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404



#ROTAS DA DIETA
@app.route('/dieta', methods=["POST"])
#@login_required
def create():
    data = request.json

   # if id_user != current_user.id and current_user.role == 'user':
   #     return jsonify({"message": "Operação não permitida"}), 403

    nome = data.get("nome")
    descricao = data.get("descricao")
    data_hora = data.get("data_hora")
    dieta = data.get("dieta")

    if nome and data_hora and dieta:
        dieta = Dieta(nome=nome, descricao=descricao, data_hora=data_hora, dieta=True)
        db.session.add(dieta)
        db.session.commit()
        return jsonify({"message": "Dieta cadastrada com sucesso"}), 200

    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/dieta/<int:id_dieta>', methods=["PUT"])
#@login_required
def update_dieta(id_dieta):    
    data = request.json
    dieta = Dieta.query.get(id_dieta)

   # if id_user != current_user.id and current_user.role == 'user':
    #    return jsonify({"message": "Operação não permitida"}), 403

    if id_dieta and (data.get("nome") or data.get("descricao") or data.get("data_hora") or data.get("dieta")):
        dieta.nome = data.get("nome")
        dieta.descricao = data.get("descricao")
        dieta.data_hora = data.get("data_hora")
        dieta.dieta = data.get("dieta")
        db.session.commit()
        return jsonify({"message": f"Dieta {id_dieta} atualizado com sucesso!"}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/dieta/<int:id_dieta>', methods=["DELETE"])
#@login_required
def delete_dieta(id_dieta):    
    dieta = Dieta.query.get(id_dieta)
    #if current_user.role != 'admin':
    #    return jsonify({"message": "Operação não permitida"}), 403
    #if id_user == current_user.id:
    #    return jsonify({"message": "Operação não permitida"}), 403
    
    if id_dieta:
        db.session.delete(dieta)
        db.session.commit()
        return jsonify({"message": f"Dieta {id_dieta} deletado com sucesso!"}), 200
    
    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route('/dieta/<int:id_dieta>', methods=["GET"])
#@login_required
def read_dieta(id_dieta):
    dieta = Dieta.query.get(id_dieta)
    if dieta:
        return {
                "nome": dieta.nome, 
                "descricao": dieta.descricao,
                "data_hora": dieta.data_hora,
                "dieta": dieta.dieta
                }
    
    return jsonify({"message": "Dieta não encontrada"}), 404

@app.route('/usuarios-com-dieta/<int:id_dieta>', methods=['GET'])
def get_usuario_dieta(id_dieta):
    user = User.query.filter_by(cd_dieta=id_dieta).all() 
    if user:
        user_list = [u.to_dict() for u in user]
        output = {
                    "Usuários": user_list,
                    "total_usuarios": len(user_list)
                }
        return jsonify(output)
    
    return jsonify({"message": "Nenhum usuário encontrado"}), 404
    
if __name__ == '__main__':
    app.run(debug=True)