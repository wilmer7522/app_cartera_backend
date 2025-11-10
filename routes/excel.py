from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from utils.auth_utils import solo_admin, obtener_usuario_actual
from database import db, usuarios_collection
import pandas as pd
from io import BytesIO
from fastapi.responses import StreamingResponse
import io

router = APIRouter(prefix="/excel", tags=["Excel"])

# === Subir Excel (solo admin) ===
@router.post("/subir")
def subir_excel(
    archivo: UploadFile = File(...),
    usuario: dict = Depends(solo_admin)
):
    """Sube un archivo Excel, lo convierte a JSON y actualiza la colección base_conocimiento"""
    try:
        if not (archivo.filename.endswith(".xlsx") or archivo.filename.endswith(".xls")):
            raise HTTPException(status_code=400, detail="El archivo debe ser formato .xlsx o .xls")

        contenido = archivo.file.read()
        df = pd.read_excel(BytesIO(contenido))

        if df.empty:
            raise HTTPException(status_code=400, detail="El archivo Excel está vacío")

        # Limpiar datos antes de guardar
        for col in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[col]):
                df[col] = df[col].apply(lambda x: x.strftime("%Y-%m-%d") if pd.notnull(x) else "")
            else:
                df[col] = df[col].fillna("")

        registros = df.to_dict(orient="records")

        base_conocimiento = db["base_conocimiento"]
        base_conocimiento.delete_many({})
        base_conocimiento.insert_many(registros)

        return {
            "mensaje": f"Archivo {archivo.filename} procesado correctamente",
            "total_registros": len(registros)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar el archivo: {e}")


# === Ver datos para dashboard ===
@router.get("/ver_dashboard")
def ver_excel_dashboard(usuario: dict = Depends(obtener_usuario_actual)):
    """
    Devuelve los datos del Excel cargado para mostrarlos en el dashboard.
    - Admin: ve todos los registros.
    - Vendedor: ve solo los registros de sus vendedores asociados.
    """
    base_conocimiento = db["base_conocimiento"]

    if usuario["rol"] == "admin":
        registros = list(base_conocimiento.find({}))
    else:
        # Vendedor
        vendedores_asociados = usuario.get("vendedores_asociados", [])
        if not vendedores_asociados:
            # No tiene asociados, no ve nada
            return {"total": 0, "datos": []}

        # Obtener todos los vendedores con su correo y nombre
        todos_vendedores = list(usuarios_collection.find({"rol": "vendedor"}, {"correo": 1, "nombre": 1}))
        correo_a_nombre = {v["correo"]: v["nombre"] for v in todos_vendedores}

        # Convertir correos de asociados a nombres
        nombres_filtrados = [correo_a_nombre.get(correo, correo).upper() for correo in vendedores_asociados]

        # Filtrar registros por nombre de vendedor
        filtro = {
            "$or": [
                {"Nombre_Vendedor": {"$regex": nombre, "$options": "i"}}
                for nombre in nombres_filtrados
            ]
        }
        registros = list(base_conocimiento.find(filtro))

    # Convertir _id a string
    for r in registros:
        r["_id"] = str(r["_id"])

    return {
        "total": len(registros),
        "datos": registros
    }


# === Subir Excel de Cupo Cartera (solo admin) ===
@router.post("/subir_cupo_cartera")
def subir_excel_cupo_cartera(
    archivo: UploadFile = File(...),
    usuario: dict = Depends(solo_admin)
):
    """
    Sube un archivo Excel (Cupo Cartera), lo convierte a JSON y actualiza la colección 'cupo_cartera'.
    Se asume que el encabezado de datos empieza en la fila 5 del Excel.
    """
    try:
        if not (archivo.filename.endswith(".xlsx") or archivo.filename.endswith(".xls")):
            raise HTTPException(
                status_code=400,
                detail="El archivo debe ser formato .xlsx o .xls"
            )

        contenido = archivo.file.read()

        # 👇 header=4 significa que los encabezados están en la fila 5
        df = pd.read_excel(BytesIO(contenido), header=4)

        if df.empty:
            raise HTTPException(status_code=400, detail="El archivo Excel está vacío")

        # Limpiar columnas (quitar espacios al inicio y final de los nombres)
        df.columns = [col.strip() for col in df.columns]

        # Limpiar datos
        for col in df.columns:
            if pd.api.types.is_datetime64_any_dtype(df[col]):
                df[col] = df[col].apply(
                    lambda x: x.strftime("%Y-%m-%d") if pd.notnull(x) else ""
                )
            else:
                df[col] = df[col].fillna("")

        registros = df.to_dict(orient="records")

        coleccion_cupo = db["cupo_cartera"]
        coleccion_cupo.delete_many({})
        coleccion_cupo.insert_many(registros)

        return {
            "mensaje": f"Archivo {archivo.filename} procesado correctamente",
            "total_registros": len(registros)
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al procesar el archivo de cupo cartera: {e}"
        )


# === Ver datos del Cupo Cartera ===
@router.get("/ver_cupo_cartera")
def ver_cupo_cartera(usuario: dict = Depends(obtener_usuario_actual)):
    """
    Devuelve los registros del Excel de cupo_cartera.
    Solo accesible para usuarios autenticados.
    """
    coleccion_cupo = db["cupo_cartera"]
    registros = list(coleccion_cupo.find({}))

    for r in registros:
        r["_id"] = str(r["_id"])

    return {
        "total": len(registros),
        "datos": registros
    }






# === Descargar Excel generado desde base_conocimiento ===

@router.post("/descargar_filtrado")
def descargar_filtrado(filtros: dict, usuario: dict = Depends(obtener_usuario_actual)):
    """
    Genera y descarga un Excel basado en los filtros activos del dashboard,
    respetando los permisos del usuario y los vendedores seleccionados.
    """
    try:
        base_conocimiento = db["base_conocimiento"]
        query = {}

        # === Si es ADMIN puede ver y filtrar libremente ===
        if usuario["rol"] == "admin":
            vendedores_filtrados = filtros.get("vendedoresSeleccionados", [])
            if vendedores_filtrados:
                query["$or"] = [
                    {"Nombre_Vendedor": {"$regex": v, "$options": "i"}}
                    for v in vendedores_filtrados
                ]

        # === Si es VENDEDOR, aplicar permisos ===
        elif usuario["rol"] == "vendedor":
            vendedores_asociados = usuario.get("vendedores_asociados", [])

            # Obtener todos los nombres de vendedores registrados
            todos_vendedores = list(
                usuarios_collection.find({"rol": "vendedor"}, {"correo": 1, "nombre": 1})
            )
            correo_a_nombre = {v["correo"]: v["nombre"] for v in todos_vendedores}

            # Convertir correos de los asociados a nombres (los que puede ver)
            nombres_autorizados = [
                correo_a_nombre.get(correo, correo) for correo in vendedores_asociados
            ]

            vendedores_filtrados = filtros.get("vendedoresSeleccionados", [])

            if vendedores_filtrados:
                # Solo los seleccionados que además estén autorizados
                vendedores_validos = [
                    v
                    for v in vendedores_filtrados
                    if v.lower() in [x.lower() for x in nombres_autorizados]
                ]
                # Si hay seleccionados válidos → usar solo esos
                if vendedores_validos:
                    query["$or"] = [
                        {"Nombre_Vendedor": {"$regex": v, "$options": "i"}}
                        for v in vendedores_validos
                    ]
                else:
                    # Si no hay válidos → usar todos los autorizados
                    query["$or"] = [
                        {"Nombre_Vendedor": {"$regex": v, "$options": "i"}}
                        for v in nombres_autorizados
                    ]
            else:
                # Si no seleccionó nada → usar todos los que puede ver
                query["$or"] = [
                    {"Nombre_Vendedor": {"$regex": v, "$options": "i"}}
                    for v in nombres_autorizados
                ]

        # === FILTRO por CLIENTE (buscador) ===
        busqueda = filtros.get("busqueda")
        if busqueda:
            query["Cliente"] = {"$regex": busqueda, "$options": "i"}

        # === FILTRO por NOTAS DE CRÉDITO ===
        if filtros.get("mostrarNotasCredito"):
            query["T_Dcto"] = {"$regex": "^NC$", "$options": "i"}

        # === FILTRO por COLUMNA SELECCIONADA ===
        columnaSeleccionada = filtros.get("columnaSeleccionada")
        if columnaSeleccionada:
            query[columnaSeleccionada] = {"$ne": 0}

        # === CONSULTA FINAL ===
        registros = list(base_conocimiento.find(query))
        if not registros:
            raise HTTPException(status_code=404, detail="No hay datos para exportar con los filtros actuales.")

        # === GENERAR EXCEL ===
        df = pd.DataFrame(registros)
        df.drop(columns=["_id"], inplace=True, errors="ignore")

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            df.to_excel(writer, index=False, sheet_name="Base_Conocimiento")

        output.seek(0)

        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": "attachment; filename=base_conocimiento_filtrado.xlsx"
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al generar el Excel filtrado: {e}")
