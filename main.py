from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import json
import requests
import datetime

from waitress import serve

app = Flask(__name__)

app.config["JWT_SECRET_KEY"]="super-secret"
jwt = JWTManager(app)


@app.before_request
def middleware():
    urlCliente = request.path
    metodoCliente = request.method

    if (urlCliente == "/login"):
        pass
    else:
        verify_jwt_in_request()

        infoToken = get_jwt_identity()
        idRol = infoToken["rol"]["_id"]

        urlValidarPermiso = dataConfig["url-backend-security"] + "/permisos-rol/validar-permiso/rol/"+idRol
        headers = {"Content-Type": "application/json"}
        print("URL CLIENTE:", urlCliente)
        bodyRequest = {
            "url": urlCliente,
            "metodo": metodoCliente
        }
        responseValidarPermiso = requests.get(urlValidarPermiso, json=bodyRequest, headers=headers)
        print("Status Code del servicio validar permiso: ", responseValidarPermiso)

        if (responseValidarPermiso.status_code == 200):
            print("El cliente SI tiene permisos")
            pass
        else:
            return {"mensaje": "Permiso denegado"}, 401




@app.route("/login", methods=["POST"])
def validarUsuario():
    print("Entro al validar usuario")
    url = dataConfig["url-backend-security"] + "/usuarios/validar-usuario"
    headers = {"Content-Type": "application/json"}
    bodyRequest = request.get_json()

    response = requests.post(url, json=bodyRequest, headers=headers)

    if (response.status_code == 200):
        print("El usuario se valido correctamente")
        infoUsuario = response.json()

        tiempoToken = datetime.timedelta(seconds=60*60)
        newToken = create_access_token(identity=infoUsuario, expires_delta=tiempoToken)

        return {"token": newToken}
    else:
        return {"mensaje": "Usuario y contraseña ERRONEOS"}, 401


@app.route("/estudiante", methods=['POST'])
def crearEstudiante():
    url = dataConfig["url-backend-academic"] + "/estudiante"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/estudiante/<string:idObject>", methods=['GET'])
def buscarEstudiante(idObject):
    url = dataConfig["url-backend-academic"] + "/estudiante/"+idObject
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)
    print("Respuesta servicio buscar estudiante: ", response)
    return response.json()

@app.route("/estudiante/<string:idObject>", methods=['GET'])
def buscarEstudiante(idObject):
    url = dataConfig["url-backend-registraduria"] + "/estudiante/"+idObject
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()


def loadFileConfig():
    with open('config.json') as propiedades:
        data = json.load(propiedades)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running: http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
