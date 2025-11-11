from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel, Field, EmailStr
from database import usuarios_collection
from passlib.hash import bcrypt
from jose import jwt
from datetime import datetime, timedelta
from utils.auth_utils import obtener_usuario_actual, solo_admin
from typing import Optional, List
import os

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"

router = APIRouter(prefix="/usuarios", tags=["Usuarios"])

# === MODELOS ===
class UsuarioRegistro(BaseModel):
    correo: EmailStr
    password: str = Field(..., min_length=4)
    nombre: str
    rol: str = "vendedor"
    vendedores_asociados: Optional[List[str]] = Field(default_factory=list)


class UsuarioLogin(BaseModel):
    correo: EmailStr
    password: str


class UsuarioUpdate(BaseModel):
    password: Optional[str] = Field(None, min_length=4)
    nombre: Optional[str] = None
    rol: Optional[str] = None
    vendedores_asociados: Optional[List[str]] = None


# === REGISTRO (público) ===
@router.post("/registro")
def registrar_usuario(datos: UsuarioRegistro):
    correo = datos.correo.strip().lower()

    if usuarios_collection.find_one({"correo": correo}):
        raise HTTPException(status_code=400, detail="❌ El correo ya está registrado")

    hashed_password = bcrypt.hash(datos.password)

    nuevo_usuario = {
        "correo": correo,
        "password": hashed_password,
        "nombre": datos.nombre.strip().upper(),
        "rol": datos.rol.strip(),
        "vendedores_asociados": [],
    }

    usuarios_collection.insert_one(nuevo_usuario)
    return {"mensaje": "✅ Usuario creado exitosamente (pendiente asignar permisos por el administrador)"}


# === LOGIN ===
'''@router.post("/login")
def login(datos: UsuarioLogin):
    correo = datos.correo.strip().lower()
    user = usuarios_collection.find_one({"correo": correo})

    if not user or not bcrypt.verify(datos.password, user["password"]):
        raise HTTPException(status_code=401, detail="❌ Credenciales inválidas")

    expira = datetime.utcnow() + timedelta(hours=6)
    token = jwt.encode({
        "correo": user["correo"],
        "rol": user.get("rol", "vendedor"),
        "exp": expira
    }, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "token": token,
        "nombre": user.get("nombre", ""),
        "rol": user.get("rol", "vendedor"),
    }'''

# === LOGIN ===
@router.post("/login")
def login(datos: UsuarioLogin):
    MAX_BCRYPT_LENGTH = 72  # ✅ Limite de bcrypt

    correo = datos.correo.strip().lower()
    user = usuarios_collection.find_one({"correo": correo})

    # Truncar la contraseña a 72 caracteres antes de verificar
    password_to_check = datos.password[:MAX_BCRYPT_LENGTH]

    if not user or not bcrypt.verify(password_to_check, user["password"]):
        raise HTTPException(status_code=401, detail="❌ Credenciales inválidas")

    expira = datetime.utcnow() + timedelta(hours=6)
    token = jwt.encode({
        "correo": user["correo"],
        "rol": user.get("rol", "vendedor"),
        "exp": expira
    }, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "token": token,
        "nombre": user.get("nombre", ""),
        "rol": user.get("rol", "vendedor"),
    }



# === PERFIL ===
@router.get("/perfil")
def ver_perfil(usuario: dict = Depends(obtener_usuario_actual)):
    return {
        "mensaje": f"Bienvenido {usuario['nombre']}, este es tu perfil",
        "vendedores_asociados": usuario.get("vendedores_asociados", [])
    }


# === LISTAR USUARIOS (solo admin) ===
@router.get("/todos")
def listar_usuarios(usuario: dict = Depends(solo_admin)):
    usuarios = list(usuarios_collection.find({}, {"password": 0}))
    for u in usuarios:
        u["_id"] = str(u["_id"])
    return {"usuarios": usuarios}


# === CREAR USUARIO (admin) ===
@router.post("/crear", dependencies=[Depends(solo_admin)])
def crear_usuario_admin(datos: UsuarioRegistro):
    correo = datos.correo.strip().lower()

    if usuarios_collection.find_one({"correo": correo}):
        raise HTTPException(status_code=400, detail="❌ El correo ya está registrado")

    hashed_password = bcrypt.hash(datos.password)

    nuevo_usuario = {
        "correo": correo,
        "password": hashed_password,
        "nombre": datos.nombre.strip().upper(),
        "rol": datos.rol.strip(),
        "vendedores_asociados": [v.strip().lower() for v in (datos.vendedores_asociados or [])],
    }

    usuarios_collection.insert_one(nuevo_usuario)
    return {"mensaje": f"✅ Usuario '{datos.nombre.strip().upper()}' creado correctamente"}


# === ACTUALIZAR USUARIO (admin) ===
@router.put("/actualizar/{correo}", dependencies=[Depends(solo_admin)])
def actualizar_usuario_admin(correo: str, datos: UsuarioUpdate = Body(...)):
    correo = correo.strip().lower()
    existente = usuarios_collection.find_one({"correo": correo})

    if not existente:
        raise HTTPException(status_code=404, detail=f"❌ Usuario con correo '{correo}' no encontrado")

    update_doc = {}

    if datos.nombre:
        update_doc["nombre"] = datos.nombre.strip().upper()
    if datos.rol:
        update_doc["rol"] = datos.rol.strip()
    if datos.password:
        update_doc["password"] = bcrypt.hash(datos.password)
    if datos.vendedores_asociados is not None:
        update_doc["vendedores_asociados"] = [v.strip().lower() for v in datos.vendedores_asociados]

    if not update_doc:
        raise HTTPException(status_code=400, detail="No hay campos para actualizar")

    usuarios_collection.update_one({"_id": existente["_id"]}, {"$set": update_doc})
    actualizado = usuarios_collection.find_one({"_id": existente["_id"]}, {"password": 0})
    actualizado["_id"] = str(actualizado["_id"])

    return {"mensaje": f"✅ Usuario '{correo}' actualizado correctamente", "usuario": actualizado}


# === ELIMINAR USUARIO (admin) ===
@router.delete("/eliminar/{correo}", dependencies=[Depends(solo_admin)])
def eliminar_usuario_admin(correo: str):
    correo = correo.strip().lower()
    res = usuarios_collection.delete_one({"correo": correo})

    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"❌ Usuario con correo '{correo}' no encontrado")

    return {"mensaje": f"🗑️ Usuario con correo '{correo}' eliminado correctamente"}
