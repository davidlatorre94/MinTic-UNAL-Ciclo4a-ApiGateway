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
import re

from waitress import serve

app = Flask(__name__)

app.config["JWT_SECRET_KEY"]="super-secret"
jwt = JWTManager(app)


@app.before_request
def middleware():

    urlAcceso = request.path
    if (urlAcceso == "/login"):
        pass
    else:
        verify_jwt_in_request()

        infoUsuario = get_jwt_identity()
        idRol = infoUsuario["rol"]["_id"]

        urlAcceso = transformarUrl(urlAcceso)

        urlValidarPermiso = dataConfig["url-backend-security"] + "/permisos-rol/validar-permiso/rol/" + idRol
        headersValidarPermiso = {"Content-Type": "application/json"}
        bodyValidarPermiso = {
            "url": urlAcceso,
            "metodo": request.method
        }
        respuestaValidarPermiso = requests.get(urlValidarPermiso, json=bodyValidarPermiso, headers=headersValidarPermiso)
        print("Respuesta validar permiso: ", respuestaValidarPermiso)

        if (respuestaValidarPermiso.status_code == 200):
            pass
        else:
            return {"mensaje": "Acceso Denegado"}, 401

def transformarUrl(urlAcceso):
    print("Url antes de transformarla: ", urlAcceso)

    partes = urlAcceso.split("/")
    print("La url dividida es:", partes)
    for palabra in partes:
        if re.search('\\d', palabra):
            urlAcceso = urlAcceso.replace(palabra, "?")

    print("Url después de transformarla:", urlAcceso)
    return urlAcceso

@app.route("/login", methods=["POST"])
def validarUsuario():

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


@app.route("/estudiante", methods=["POST"])
def crearEstudiante():
    url = dataConfig["url-backend-academic"] + "/estudiante"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.post(url, json=body, headers=headers)

    return response.json()

@app.route("/estudiante/<string:idObject>", methods=['GET'])
def buscarEstudiante(idObject):
    url = dataConfig["url-backend-academic"] + "/estudiante/" + idObject
    headers = {"Content-Type": "application/json"}

    response = requests.get(url, headers=headers)

    return response.json()

@app.route("/estudiante", methods=['GET'])
def buscarTodosLosEstudiantes():
    url = dataConfig["url-backend-academic"] + "/estudiante"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

@app.route("/estudiante", methods=['PUT'])
def actualizarEstudiante():
    url = dataConfig["url-backend-academic"] + "/estudiante"
    headers = {"Content-Type": "application/json"}
    body = request.get_json()

    response = requests.put(url, json=body, headers=headers)
    return response.json()

@app.route("/estudiante/<string:idObject>", methods=['DELETE'])
def eliminarEstudiante(idObject):
    url = dataConfig["url-backend-academic"] + "/estudiante/"+idObject
    headers = {"Content-Type": "application/json"}

    response = requests.delete(url, headers=headers)
    return response.json()

def loadFileConfig():
    with open('config.json') as propiedades:
        data = json.load(propiedades)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running: http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])
