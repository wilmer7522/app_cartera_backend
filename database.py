# === backend/database.py ===
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Cargar variables desde el archivo .env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["cartera_db"]

usuarios_collection = db["usuarios"]
clientes_collection = db["clientes"]

print("✅ Conexión exitosa con MongoDB Atlas")
