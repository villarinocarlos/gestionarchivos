from django.http import HttpResponse, FileResponse,HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
import os
from datetime import datetime
from .google_drive import upload_to_drive,get_gdrive_service
import mimetypes
from .firebase import db
from .forms import ArchivoForm, CrearUsuarioForm
import mimetypes
from django.core.paginator import Paginator
import hashlib
from django.urls import reverse
import logging
from django.contrib import messages
from django.db import transaction
from django.shortcuts import redirect, render
import hashlib
from .firebase import db
from .forms import ArchivoForm
from django.views.decorators.cache import cache_control
import glob
import pytz
from django.utils.timezone import get_current_timezone
import plotly.express as px
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak
from reportlab.lib.units import inch
from django.http import FileResponse
from io import BytesIO
from reportlab.pdfgen import canvas


CREDENTIALS_FILE = 'gestion_archivos/credentials/long-star-438815-m0-afb3b41c32e4.json'


FOLDER_ID = '1NhdiFATcawAk2nOUlpMGmu10qQq_pIyU'  

def login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if 'usuario' not in request.session:
            return redirect('login')  
        return view_func(request, *args, **kwargs)
    return wrapper

def obtener_servicio_gdrive():
    """Obtiene el servicio de Google Drive autenticado con las credenciales."""
    SCOPES = ['https://www.googleapis.com/auth/drive']
    creds = service_account.Credentials.from_service_account_file(CREDENTIALS_FILE, scopes=SCOPES)
    servicio = build('drive', 'v3', credentials=creds)
    return servicio

def subir_a_drive(file_path, file_name):
    service = get_gdrive_service()
    
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'  
    
    file_metadata = {
        'name': file_name,
        'parents': [FOLDER_ID]
    }
    
    media = MediaFileUpload(file_path, mimetype=mime_type, resumable=True)
    
    try:
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        return file.get('id')
    except Exception as e:
        print(f"Error al subir archivo a Google Drive: {e}")
        raise

@login_required
def pagina_principal(request):
    archivos_lista = obtener_todos_los_archivos_desde_firebase()

    
    if not isinstance(archivos_lista, list):
        print(f"archivos_lista no es una lista: {archivos_lista}")
        archivos_lista = []

    
    search_query = request.GET.get('search', '')
    if search_query:
        
        try:
            archivos_lista = [
                archivo for archivo in archivos_lista 
                if isinstance(archivo, dict) and (
                  'Nombre' in archivo and search_query.lower() in archivo['Nombre'].lower() or
                    'FechaCreacion' in archivo and search_query.lower() in archivo['FechaCreacion'].lower() or
                    'Oficio' in archivo and search_query.lower() in archivo['Oficio'].lower() or
                    'Estado' in archivo and search_query.lower() in archivo['Estado'].lower() or
                    'Destinatario' in archivo and search_query.lower() in archivo['Destinatario'].lower()
                )
            ]
        except Exception as e:
            print(f"Error al filtrar archivos: {e}")
            archivos_lista = []

    paginator = Paginator(archivos_lista, 10)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'pagina_principal.html', {'page_obj': page_obj, 'search_query': search_query})

def obtener_todos_los_archivos_desde_firebase():
    try:
        archivos = db.child("Archivos").get()  
        if archivos.each():  
            archivos_lista = [archivo.val() for archivo in archivos.each()]  
            return archivos_lista  
        else:
            return []  
    except Exception as e:
        print(f"Error al obtener archivos desde Firebase: {e}")
        return []
from django.shortcuts import redirect, render
import hashlib
from .firebase import db
from .forms import ArchivoForm


logger = logging.getLogger('custom')

@login_required
def subir_archivo(request):
    if request.method == 'POST':
        form = ArchivoForm(request.POST, request.FILES)
        if form.is_valid():
            archivo = request.FILES.get('Archivo')  
            if archivo:
                file_path = f'/tmp/{archivo.name}'

                
                with open(file_path, 'wb') as f:
                    for chunk in archivo.chunks():
                        f.write(chunk)

                
                sha256_hash = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in f:
                        sha256_hash.update(chunk)
                archivo_hash = sha256_hash.hexdigest()

                
                archivos_existentes = db.child("Archivos").order_by_child("Hash").equal_to(archivo_hash).get()
                if archivos_existentes.each():
                    form.add_error(None, "Este archivo ya ha sido subido anteriormente.")
                    return render(request, 'subir_archivo.html', {'form': form})

                
                file_id = subir_a_drive(file_path, archivo.name)

                db.child("Archivos").push({
                    "Nombre": form.cleaned_data['Nombre'],
                    "FechaCreacion": form.cleaned_data['FechaCreacion'].strftime('%Y-%m-%d'),
                    "Estado": form.cleaned_data['Estado'],
                    "Tipo": form.cleaned_data['Tipo'],
                    "Procedencias": form.cleaned_data['Procedencias'],
                    "Destinatario": form.cleaned_data['Destinatario'],
                    "Oficio": form.cleaned_data['Oficio'],
                    "Asunto": form.cleaned_data['Asunto'],
                    "ID_Archivo": file_id,
                    "Hash": archivo_hash,
                    "URL": f'https://drive.google.com/file/d/{file_id}/view',
                })

                logger.info(f"[Subida de Archivo] Archivo '{archivo.name}' subido exitosamente por {request.session['usuario']['nombre']}")
                return redirect('pagina_principal')
    else:
        form = ArchivoForm()

    return render(request, 'subir_archivo.html', {'form': form})

@login_required
def lista_archivos(request):
    archivos = db.child("Archivos").get().val()
    archivos_list = archivos.values() if archivos else []

    context = {'archivos': archivos_list}
    return render(request, 'pagina_principal.html', context)


def obtener_archivo_desde_firebase(id_archivo):
    archivo = db.child("Archivos").order_by_child("ID_Archivo").equal_to(id_archivo).get()
    archivo_dict = archivo.val()
    
    if not archivo_dict:
        print(f"Archivo con ID_Archivo {id_archivo} no encontrado en Firebase")  
        return None
    
    
    for key, archivo_data in archivo_dict.items():
        return archivo_data

@login_required   
def ver_archivo(request, archivo_id):
    archivo = obtener_archivo_desde_firebase(archivo_id)
    
    if archivo is None:
        return HttpResponse("Archivo no encontrado en Firebase", status=404)
    
    if 'URL' not in archivo:
        return HttpResponse("No se puede acceder al archivo: no tiene una URL válida.", status=404)
    
    url_drive = archivo['URL']
    return redirect(url_drive)

@login_required
def descargar_archivo(request, archivo_id):
    archivo = db.child("Archivos").child(archivo_id).get().val()
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{archivo["Nombre"]}"'
    
    return response
def borrar_de_drive(file_id):
    """Elimina un archivo de Google Drive usando su file_id."""
    try:
        service = get_gdrive_service()  
        service.files().delete(fileId=file_id).execute()  
        print(f"Archivo con ID {file_id} eliminado de Google Drive.")
    except Exception as e:
        print(f"Error al borrar archivo de Google Drive: {e}")
        raise

logger = logging.getLogger('custom')

def borrar_archivo(request, archivo_id):
    usuario_actual = request.session.get('usuario')
    if not usuario_actual or usuario_actual.get('rol') != 'Admin':
        messages.error(request, "No tienes permiso para borrar archivos.")
        return redirect('pagina_principal')

    archivo = obtener_archivo_desde_firebase(archivo_id)
    if archivo is None:
        messages.error(request, "Archivo no encontrado.")
        return redirect('pagina_principal')

    try:
        archivo_en_firebase = db.child("Archivos").order_by_child("ID_Archivo").equal_to(archivo_id).get()
        if archivo_en_firebase.each():
            archivo_key = archivo_en_firebase.each()[0].key()  

            try:
                file_id = archivo.get("ID_Archivo")  
                if file_id:
                    borrar_de_drive(file_id)  
            except Exception as e:
                print(f"Error al borrar el archivo de Google Drive: {e}")
                messages.error(request, "Error al borrar el archivo en Google Drive.")
                return redirect('pagina_principal')

            db.child("Archivos").child(archivo_key).remove()
            messages.success(request, "Archivo borrado correctamente.")
            
            
            logger.info(f"[Borrado de Archivo] Archivo '{archivo_id}' borrado exitosamente por {usuario_actual['nombre']}")
            return redirect('pagina_principal')
        else:
            messages.error(request, "Archivo no encontrado para borrar.")
            return redirect('pagina_principal')

    except Exception as e:
        messages.error(request, f"Error al intentar borrar el archivo: {e}")
        return redirect('pagina_principal')
    
logger = logging.getLogger('custom')
@login_required
def editar_archivo(request, archivo_id):
    try:
        archivo_query = db.child("Archivos").order_by_child("ID_Archivo").equal_to(archivo_id).get()

        if not archivo_query.each():
            return HttpResponse("Archivo no encontrado", status=404)

        archivo_data = archivo_query.val()
        archivo_clave = list(archivo_data.keys())[0]
        archivo_info = archivo_data[archivo_clave]

        if request.method == 'POST':
            form = ArchivoForm(request.POST, edit_mode=True, archivo_id=archivo_id)  
            if form.is_valid():
                
                db.child("Archivos").child(archivo_clave).update({
                    "Nombre": form.cleaned_data['Nombre'],
                    "FechaCreacion": form.cleaned_data['FechaCreacion'].strftime('%Y-%m-%d'),
                    "Estado": form.cleaned_data['Estado'],
                    "Tipo": form.cleaned_data['Tipo'],
                    "Procedencias": form.cleaned_data['Procedencias'],
                    "Destinatario": form.cleaned_data['Destinatario'],
                    "Oficio": form.cleaned_data['Oficio'],
                    "Asunto": form.cleaned_data['Asunto'],
                })
                
                
                logger.info(f"[Edición de Archivo] Archivo '{archivo_id}' editado exitosamente por {request.session['usuario']['nombre']}")
                return redirect('pagina_principal')
        else:
            form = ArchivoForm(initial={
                'Nombre': archivo_info.get('Nombre', ''),
                'FechaCreacion': archivo_info.get('FechaCreacion', ''),
                'Estado': archivo_info.get('Estado', ''),
                'Tipo': archivo_info.get('Tipo', ''),
                'Procedencias': archivo_info.get('Procedencias', ''),
                'Destinatario': archivo_info.get('Destinatario', ''),
                'Oficio': archivo_info.get('Oficio', ''),
                'Asunto': archivo_info.get('Asunto', ''),
            }, edit_mode=True, archivo_id=archivo_id)

        return render(request, 'editar_archivo.html', {'form': form, 'archivo_info': archivo_info})

    except Exception as e:
        return HttpResponse(f"Error al obtener archivo desde Firebase: {e}", status=500)
@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def admin_page(request):
    
    usuario_actual = request.session.get('usuario')
    
    
    if usuario_actual and usuario_actual.get('rol') == 'Admin':
        usuarios = []  

        
        usuarios_ref = db.child("usuarios").get()
        if usuarios_ref.each():
            for usuario in usuarios_ref.each():
                usuarios.append(usuario.val())

        context = {
            'usuarios': usuarios 
        }
        
        return render(request, 'admin_page.html', context)  
    else:
       
        return redirect('pagina_principal')
    
logger = logging.getLogger('custom')

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def crear_usuario(request):
    
    usuario_actual = request.session.get('usuario')
    if not usuario_actual or usuario_actual.get('rol') != 'Admin':
        messages.error(request, "No tienes permiso para acceder a esta página.")
        return redirect('pagina_principal')  

    if request.method == 'POST':
        form = CrearUsuarioForm(request.POST)
        
        if form.is_valid():
            correo = form.cleaned_data['Correo']
            
            if usuario_existe(correo):
                form.add_error('Correo', 'El correo ya está registrado para otro usuario.')
            else:
                nombre = form.cleaned_data['Nombre']
                rol = form.cleaned_data['Rol']
                contraseña = form.cleaned_data['Contraseña']

                
                usuarios = db.child("usuarios").get()
                nuevo_id_usuario = len(usuarios.val()) + 1 if usuarios.val() else 1

                
                db.child("usuarios").push({
                    "Correo": correo,
                    "ID_Usuario": nuevo_id_usuario,
                    "Nombre": nombre,
                    "Rol": rol,
                    "contraseña": contraseña
                })

                
                logger.info(f"[Creación de Usuario] Usuario '{nombre}' creado exitosamente por {usuario_actual['nombre']}")
                return redirect('admin_page')  
    else:
        form = CrearUsuarioForm()

    return render(request, 'crear_usuario.html', {'form': form})

logger = logging.getLogger('custom')

def login_view(request):
    
    if 'usuario' in request.session:
        return redirect('pagina_principal')

    correo_error = None
    contrasena_error = None

    if request.method == 'POST':
        correo = request.POST.get('correo')
        contrasena = request.POST.get('contrasena')

        
        if not correo:
            correo_error = 'Debes ingresar tu correo electrónico.'
        if not contrasena:
            contrasena_error = 'Debes ingresar tu contraseña.'

        
        if correo_error or contrasena_error:
            return render(request, 'login.html', {'correo_error': correo_error, 'contrasena_error': contrasena_error})

        
        if '@' not in correo:
            messages.error(request, 'El correo ingresado no es válido.')
            return render(request, 'login.html')

        
        usuarios = db.child("usuarios").order_by_child("Correo").equal_to(correo).get()

        if usuarios.each():
            for usuario in usuarios.each():
                datos_usuario = usuario.val()
                
                if datos_usuario.get('contraseña') == contrasena:
                    
                    request.session['usuario'] = {
                        'nombre': datos_usuario.get('Nombre'),
                        'correo': datos_usuario.get('Correo'),
                        'rol': datos_usuario.get('Rol')
                    }
                    
                    logger.info(f"[Login] Inicio de sesión exitoso - Usuario: {datos_usuario.get('Nombre')} ({correo})")
                    return redirect('pagina_principal')
                else:
                    messages.error(request, 'Contraseña incorrecta.')
        else:
            messages.error(request, 'El correo no está registrado.')

    
    response = render(request, 'login.html', {'correo_error': correo_error, 'contrasena_error': contrasena_error})
    response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    return response


logger = logging.getLogger('custom')

def logout_view(request):
    usuario_actual = request.session.get('usuario')
    
    
    if usuario_actual:
        logger.info(f"[Logout] Cierre de sesión exitoso para el usuario {usuario_actual['nombre']}")

    
    request.session.flush()
   
    return redirect('login')



logger = logging.getLogger('custom')

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def editar_usuario(request, usuario_id):
    
    usuario_actual = request.session.get('usuario')
    if not usuario_actual or usuario_actual.get('rol') != 'Admin':
        messages.error(request, "No tienes permiso para acceder a esta página.")
        return redirect('pagina_principal')  

    usuario_ref = db.child("usuarios").order_by_child("ID_Usuario").equal_to(usuario_id).get()
    usuario_data = usuario_ref.each()[0].val() if usuario_ref.each() else None

    if not usuario_data:
        return redirect('admin_page')

    if request.method == 'POST':
        form = CrearUsuarioForm(request.POST, usuario_id=usuario_id)

        if form.is_valid():
            correo = form.cleaned_data['Correo']
            
            if usuario_existe(correo) and correo != usuario_data.get('Correo'):
                form.add_error('Correo', 'El correo ya está registrado para otro usuario.')
            else:
                nombre = form.cleaned_data['Nombre']
                rol = form.cleaned_data['Rol']
                contraseña = form.cleaned_data['Contraseña']
                
                db.child("usuarios").child(usuario_ref.each()[0].key()).update({
                    "Correo": correo,
                    "Nombre": nombre,
                    "Rol": rol,
                    "contraseña": contraseña
                })

                
                logger.info(f"[Edición de Usuario] Usuario '{nombre}' (ID: {usuario_id}) editado exitosamente por {usuario_actual['nombre']}")
                return redirect('admin_page')
    else:
        form = CrearUsuarioForm(initial={
            'Nombre': usuario_data.get('Nombre'),
            'Correo': usuario_data.get('Correo'),
            'Rol': usuario_data.get('Rol'),
            'Contraseña': usuario_data.get('contraseña')
        }, usuario_id=usuario_id)

    return render(request, 'editar_usuario.html', {'form': form, 'usuario_id': usuario_id})

def usuario_existe(correo):
    """
    Verifica si un usuario con el correo dado ya existe en Firebase.
    """
    usuarios_con_correo = db.child("usuarios").order_by_child("Correo").equal_to(correo).get()
    
    return any(usuarios_con_correo.each())

logger = logging.getLogger('custom')

def eliminar_usuario(request, usuario_id):
    
    usuario_ref = db.child("usuarios").order_by_child("ID_Usuario").equal_to(usuario_id).get()
    if usuario_ref.each():
        usuario_key = usuario_ref.each()[0].key()  
        usuario_data = usuario_ref.each()[0].val()
        db.child("usuarios").child(usuario_key).remove()  

        
        logger.info(f"[Borrado de Usuario] Usuario '{usuario_data['Nombre']}' (ID: {usuario_id}) eliminado exitosamente por {request.session['usuario']['nombre']}")

        
        if request.resolver_match.url_name == 'admin_page':
            messages.success(request, "Usuario eliminado correctamente.")
    else:
        if request.resolver_match.url_name == 'admin_page':
            messages.error(request, "No se pudo encontrar el usuario para eliminar.")
    
    
    return redirect('admin_page')

def obtener_logs():
    ruta_logs = os.path.join(os.path.dirname(__file__), '../logs/actions.log*')
    logs = []

    try:
        log_files = sorted(glob.glob(ruta_logs))
        for log_file_path in log_files:
            with open(log_file_path, 'r') as archivo:
                for linea in archivo:
                    parts = linea.strip().split(' - ')
                    if len(parts) >= 3:
                        timestamp_str = parts[0]
                        level = parts[1].strip()
                        message = ' - '.join(parts[2:])
                        
                        
                        if 'Watching for file changes' in message or 'GET /' in message or 'POST /' in message:
                            continue

                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                        logs.append({
                            'timestamp': timestamp,
                            'level': level,
                            'message': message,
                        })
    except Exception as e:
        logs.append({'timestamp': datetime.now(), 'level': 'ERROR', 'message': str(e)})

    
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return logs

def extract_user_from_activity(activity):
    if 'Usuario:' in activity:
        return activity.split('Usuario: ')[1].split(' ')[0]
    elif 'por' in activity:
        return activity.split('por ')[1].split(' ')[0]
    return 'Desconocido'

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def ver_logs(request):
    usuario_actual = request.session.get('usuario')
    if not usuario_actual or usuario_actual.get('rol') != 'Admin':
        messages.error(request, "No tienes permiso para acceder a los registros de administración.")
        return redirect('pagina_principal')
    
    logs = obtener_logs_formateados()

    
    search_query = request.GET.get('search', '')
    if search_query:
        logs = [log for log in logs if (
            search_query.lower() in log['message'].lower() or 
            search_query.lower() in log['level'].lower() or
            search_query in log['timestamp']  
        )]

    paginator = Paginator(logs, 10)  
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    
    return render(request, 'logs.html', {
        'page_obj': page_obj, 
        'search_query': search_query
    })

def obtener_logs_directos():
    ruta_logs = os.path.join(os.path.dirname(__file__), '..', 'logs', 'actions.log*')
    logs = []

    try:
        log_files = sorted(glob.glob(ruta_logs))
        for log_file_path in log_files:
            with open(log_file_path, 'r') as archivo:
                logs.extend(archivo.readlines())
    except FileNotFoundError:
        logs.append("Archivo de logs no encontrado.")
    except Exception as e:
        logs.append(f"Error al leer los logs: {e}")
    
    return logs

def obtener_logs_formateados():
    ruta_logs = os.path.join(os.path.dirname(__file__), '../logs/actions.log*')
    logs = []

    try:
        log_files = sorted(glob.glob(ruta_logs))
        for log_file_path in log_files:
            with open(log_file_path, 'r') as archivo:
                for linea in archivo:
                    parts = linea.strip().split(' - ')
                    if len(parts) >= 3:
                        timestamp_str = parts[0]
                        level = parts[1].strip()
                        message = ' - '.join(parts[2:])
                        
                        
                        if any(substring in message for substring in [
                            "Watching for file changes", "GET /", "POST /", 
                            "favicon.ico", "reloading", "Internal Server Error", "Broken pipe"]):
                            continue

                        
                        usuario = None
                        if "Usuario:" in message:
                            usuario = message.split("Usuario: ")[1].split()[0]  

                        
                        utc_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                        local_time = utc_time.astimezone(pytz.timezone('America/Merida'))
                        
                        logs.append({
                            'timestamp': local_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'level': level,
                            'message': message,
                            'usuario': usuario,  
                        })
    except Exception as e:
        logs.append({'timestamp': datetime.now(pytz.timezone('America/Merida')).strftime('%Y-%m-%d %H:%M:%S'), 'level': 'ERROR', 'message': str(e)})

    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return logs

def convertir_a_timezone(timestamp_str, timezone='America/Merida'):
    naive_datetime = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
    local_tz = pytz.timezone(timezone)
    localized_datetime = pytz.utc.localize(naive_datetime).astimezone(local_tz)
    return localized_datetime.strftime('%Y-%m-%d %H:%M:%S')

@login_required
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def reportes_auditoria(request):
    usuario_actual = request.session.get('usuario')
    if not usuario_actual or usuario_actual.get('rol') != 'Admin':
        messages.error(request, "No tienes permiso para acceder a los reportes de auditoría.")
        return redirect('pagina_principal')

    
    logs = obtener_logs_formateados()

   
    df = pd.DataFrame(logs)

    
    archivos_subidos = df.loc[df['level'] == 'INFO']
    archivos_subidos = archivos_subidos[archivos_subidos['message'].str.contains("subido")]
    archivos_subidos['usuario'] = archivos_subidos['message'].apply(lambda x: extract_user_from_activity(x))

    
    archivos_subidos = archivos_subidos[archivos_subidos['usuario'] != 'Desconocido']

    
    logs_por_usuario = archivos_subidos['usuario'].value_counts().reset_index()
    logs_por_usuario.columns = ['Usuario', 'Cantidad']

    
    graph_usuario = px.bar(logs_por_usuario, x='Usuario', y='Cantidad',
                            title='Cantidad de Archivos Subidos por Usuario',
                            labels={'Usuario': 'Usuario', 'Cantidad': 'Cantidad'}, color='Cantidad')
    graph_usuario_html = graph_usuario.to_html(full_html=False)

    
    archivos_editados = df.loc[df['level'] == 'INFO']
    archivos_editados = archivos_editados[archivos_editados['message'].str.contains("editado")]
    archivos_editados['usuario'] = archivos_editados['message'].apply(lambda x: extract_user_from_activity(x))

    
    archivos_editados = archivos_editados[archivos_editados['usuario'] != 'Desconocido']
    logs_por_usuario_editados = archivos_editados['usuario'].value_counts().reset_index()
    logs_por_usuario_editados.columns = ['Usuario', 'Cantidad']

    graph_editados = px.bar(logs_por_usuario_editados, x='Usuario', y='Cantidad',
                            title='Cantidad de Archivos Editados por Usuario',
                            labels={'Usuario': 'Usuario', 'Cantidad': 'Cantidad'}, color='Cantidad')
    graph_editados_html = graph_editados.to_html(full_html=False)

    archivos_borrados = df.loc[df['level'] == 'INFO']
    archivos_borrados = archivos_borrados[archivos_borrados['message'].str.contains("borrado")]
    archivos_borrados['usuario'] = archivos_borrados['message'].apply(lambda x: extract_user_from_activity(x))

    
    archivos_borrados = archivos_borrados[archivos_borrados['usuario'] != 'Desconocido']
    logs_por_usuario_borrados = archivos_borrados['usuario'].value_counts().reset_index()
    logs_por_usuario_borrados.columns = ['Usuario', 'Cantidad']

    graph_borrados = px.bar(logs_por_usuario_borrados, x='Usuario', y='Cantidad',
                            title='Cantidad de Archivos Borrados por Usuario',
                            labels={'Usuario': 'Usuario', 'Cantidad': 'Cantidad'}, color='Cantidad')
    graph_borrados_html = graph_borrados.to_html(full_html=False)

    
    return render(request, 'reportes_auditoria.html', {
        'graph_usuario_html': graph_usuario_html,
        'graph_editados_html': graph_editados_html,
        'graph_borrados_html': graph_borrados_html,
    })

logger = logging.getLogger('custom')
@login_required
def reportar_archivos(request):
    return generar_informe_pdf(request)

@login_required
def generar_informe_pdf(request):
    # Obtener la fecha de los archivos a generar
    fecha_reporte = request.GET.get('fecha', None)

    # Obtener todos los archivos desde Firebase
    archivos_data = obtener_todos_los_archivos_desde_firebase()
    
    # Filtrar los archivos por fecha
    if fecha_reporte:
        archivos_data = [archivo for archivo in archivos_data if isinstance(archivo, dict) and archivo.get("FechaCreacion") == fecha_reporte]
    
    # Verifica que archivos_data sea una lista de diccionarios
    if not isinstance(archivos_data, list) or not all(isinstance(item, dict) for item in archivos_data):
        logger.error("Los datos de archivos no son válidos.")
        return HttpResponse("Error: Los datos de archivos no son válidos.", status=400)

    # Creamos un buffer para guardar el PDF
    buffer = BytesIO()
    pdf = SimpleDocTemplate(buffer, pagesize=letter)

    # Títulos
    title = "Instituto Campechano"
    subtitle = "Unidad de Transparencia y Acceso a la Información Pública"

    # Cabecera de la tabla
    header = [
        ['Nombre', 'Asunto', 'Destinatario', 'Oficio', 'Procedencia', 'Tipo', 'Estado', 'Fecha de Creación']
    ]
    
    # Extraemos la información necesaria
    data = header + [[
        archivo.get("Nombre", ""),
        archivo.get("Asunto", ""),
        archivo.get("Destinatario", ""),
        archivo.get("Oficio", ""),
        archivo.get("Procedencias", ""),
        archivo.get("Tipo", ""),
        archivo.get("Estado", ""),
        archivo.get("FechaCreacion", "")
    ] for archivo in archivos_data]

    # Definición del ancho de las columnas
    col_widths = [1.0 * inch] * len(header[0])  # Ajustar aquí el ancho según sea necesario

    # Crear la tabla
    table = Table(data, colWidths=col_widths)

    # Estilo de la tabla
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])
    
    table.setStyle(style)

    # Generar el contenido del PDF
    elements = []
    elements.append(table)

    # Footer con la información requerida
    footer = """
    www.transparencia.instcamp.edu.mx
    transparencia@instcamp.edu.mx
    CALLE 10 #357 COLONIA CENTRO
    CP 24000
    +52 (981) 81112975
    +52 (981) 8162480
    """

    # Crear un estilo para el pie de página
    styles = getSampleStyleSheet()
    footer_paragraph = Paragraph(footer.replace('\n', '<br/>'), styles['Normal'])

    elements.append(footer_paragraph)

    # Generar el PDF
    pdf.build(elements)

    buffer.seek(0)  # Mueve el puntero al principio del buffer

    # Generar la respuesta HTTP
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="informe_archivos.pdf"'
    return response