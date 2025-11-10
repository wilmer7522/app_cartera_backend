from pymongo import MongoClient
from passlib.hash import bcrypt
from dotenv import load_dotenv
import os

# Cargar variables de entorno (.env)
load_dotenv()

# Conectarse al cluster de MongoDB Atlas
client = MongoClient(os.getenv("MONGO_URI"))
db = client["cartera_db"]
usuarios = db["usuarios"]

# Datos del administrador inicial
admin = {
    "correo": "wilmer7522@gmail.com",
    "password": bcrypt.hash("1234"),
    "nombre": "WILMER ROJAS",
    "rol": "admin",  # 👈 importante: debe ser "admin" exactamente
    "vendedores_asociados": []
}

# Verificar si ya existe
if usuarios.find_one({"correo": admin["correo"]}):
    print("⚠️ Ya existe un usuario con ese correo.")
else:
    usuarios.insert_one(admin)
    print("✅ Usuario administrador creado correctamente.")
