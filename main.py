# === backend/main.py ===
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import usuarios, excel


app = FastAPI(
    title="App Cartera",
    version="1.0.0",
    description="Sistema para gestión de vendedores, clientes y base de conocimiento."
)


# CORS para permitir peticiones desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"mensaje": "Servidor FastAPI funcionando 🚀"}

# Rutas
app.include_router(usuarios.router)
app.include_router(excel.router)
