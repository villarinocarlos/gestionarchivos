import pyrebase


config = {
    "apiKey": "AIzaSyCrQNljuBIojr9wBzOdpSnKfs0x8UeSKIQ",
    "authDomain": "gestion-archivos-10eae.firebaseapp.com",
    "databaseURL": "https://gestion-archivos-10eae-default-rtdb.firebaseio.com",
    "projectId": "gestion-archivos-10eae",
    "storageBucket": "gestion-archivos-10eae.appspot.com",
    "messagingSenderId": "332097588405",
    "appId": "1:332097588405:web:23063bbead14c76e8fc2fc",
    "measurementId": "G-WSD275EVV8" 
}

firebase = pyrebase.initialize_app(config)
db = firebase.database()


def obtener_todos_los_archivos_desde_firebase():
    try:
        archivos = db.child("Archivos").get()
        archivos_lista = []

        if archivos.each():
            for archivo in archivos.each():
                archivo_data = archivo.val()
                if isinstance(archivo_data, dict):
                    archivos_lista.append(archivo_data)
                else:
                    print(f"Elemento no válido encontrado: {archivo_data}")

            print("Archivos obtenidos:", archivos_lista)  # Verifica la salida aquí
            return archivos_lista
        else:
            print("No se encontraron archivos en Firebase.")
            return []
    except Exception as e:
        print(f"Error al obtener archivos desde Firebase: {e}")
        return []
