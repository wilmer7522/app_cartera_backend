# backend/utils/auth_utils.py
from fastapi import Depends, HTTPException, Header
from jose import jwt, JWTError
from database import db

SECRET_KEY = "clave_super_secreta"
ALGORITHM = "HS256"

usuarios_collection = db["usuarios"]


# === Verifica el token y obtiene el usuario actual ===
def obtener_usuario_actual(authorization: str = Header(...)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token no proporcionado o inválido")

    token = authorization.split(" ")[1]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # ✅ Ahora usamos 'correo' en lugar de 'usuario'
        correo = payload.get("correo")
        if not correo:
            raise HTTPException(status_code=401, detail="Token sin correo válido")

        usuario = usuarios_collection.find_one({"correo": correo})
        if not usuario:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")

        return usuario

    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


# === Restringe acceso solo a administradores ===
def solo_admin(usuario: dict = Depends(obtener_usuario_actual)):
    if usuario.get("rol") != "admin":
        raise HTTPException(status_code=403, detail="Solo el administrador puede realizar esta acción")
    return usuario

