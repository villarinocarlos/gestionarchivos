from django import forms
import re
import datetime
import hashlib
from .firebase import db


class ArchivoForm(forms.Form):
    Nombre = forms.CharField(
        max_length=50,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El nombre no puede tener más de 50 caracteres.'
        }
    )
    FechaCreacion = forms.DateField(
        error_messages={
            'required': 'Este campo es obligatorio.',
            'invalid': 'Ingrese una fecha válida.'
        }
    )
    Estado = forms.CharField(
        max_length=20,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El estado no puede tener más de 20 caracteres.'
        }
    )
    Tipo = forms.CharField(
        max_length=30,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El tipo no puede tener más de 30 caracteres.'
        }
    )
    Procedencias = forms.CharField(
        max_length=100,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'La procedencia no puede tener más de 100 caracteres.'
        }
    )
    Destinatario = forms.CharField(
        max_length=100,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El destinatario no puede tener más de 100 caracteres.'
        }
    )
    Oficio = forms.CharField(
        max_length=50,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El número de oficio no puede tener más de 50 caracteres.'
        }
    )
    Asunto = forms.CharField(
        max_length=200,
        widget=forms.Textarea,
        error_messages={
            'required': 'Este campo es obligatorio.',
            'max_length': 'El asunto no puede tener más de 200 caracteres.'
        }
    )

    Archivo = forms.FileField(
        required=False,
        error_messages={
            'required': 'Debes subir un archivo.',
        }
    )

    def __init__(self, *args, **kwargs):
        self.edit_mode = kwargs.pop('edit_mode', False) 
        self.current_id = kwargs.pop('archivo_id', None)  
        super(ArchivoForm, self).__init__(*args, **kwargs)
        if self.edit_mode:
            self.fields['Archivo'].required = False  

    def clean_Nombre(self):
        nombre = self.cleaned_data.get('Nombre')

        if not nombre:
            raise forms.ValidationError("El campo Nombre es obligatorio.")

        archivo_existente = db.child("Archivos").order_by_child("Nombre").equal_to(nombre).get()

        if archivo_existente.each():
            for archivo in archivo_existente.each():
                
                if not self.edit_mode or (self.current_id and archivo.val()["ID_Archivo"] != self.current_id):
                    raise forms.ValidationError("Ya existe un archivo con este nombre.")

        if not re.match(r'^[A-Za-z0-9\s]+$', nombre):
            raise forms.ValidationError("El nombre no puede contener caracteres especiales.")

        return nombre

    def clean_Archivo(self):
        archivo = self.cleaned_data.get('Archivo')
        if archivo:
            ext = archivo.name.split('.')[-1].lower()
            valid_exts = ['pdf', 'doc', 'docx', 'xls', 'xlsx']
            if ext not in valid_exts:
                raise forms.ValidationError("Solo se permiten archivos PDF, Word o Excel.")

            sha256_hash = hashlib.sha256()
            for chunk in archivo.chunks():
                sha256_hash.update(chunk)
            archivo_hash = sha256_hash.hexdigest()

            archivo_existente = db.child("Archivos").order_by_child("Hash").equal_to(archivo_hash).get()
            if archivo_existente.each():
                raise forms.ValidationError("Ya existe un archivo con el mismo contenido.")

            if archivo.size > 5 * 1024 * 1024:  # 5 MB
                raise forms.ValidationError("El archivo no debe superar los 5 MB.")

        return archivo

    def clean_FechaCreacion(self):
        fecha = self.cleaned_data.get('FechaCreacion')
        if fecha > datetime.date.today():
            raise forms.ValidationError("La fecha no puede ser futura.")
        return fecha

def clean(self):
    cleaned_data = super().clean()
    archivo = cleaned_data.get('Archivo')
    
    if not self.edit_mode and not archivo:
        raise forms.ValidationError("Debes subir un archivo.")
    
    return cleaned_data


class CrearUsuarioForm(forms.Form):
    Nombre = forms.CharField(
        max_length=100,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nombre del usuario'
        }),
        error_messages={'required': 'Este campo es obligatorio.'}
    )
    Correo = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Correo electrónico'
        }),
        error_messages={'required': 'Por favor, introduce un correo electrónico válido.'}
    )
    Rol = forms.ChoiceField(
        choices=[('Admin', 'Admin'), ('Usuario', 'Usuario')],
        widget=forms.Select(attrs={'class': 'form-control'}),
        error_messages={'required': 'Por favor, selecciona un rol.'}
    )
    Contraseña = forms.CharField(
        max_length=100,
        required=True,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña'
        }),
        error_messages={'required': 'Este campo es obligatorio.'}
    )

    def __init__(self, *args, **kwargs):
        
        self.db = kwargs.pop('db', None)
        self.usuario_id = kwargs.pop('usuario_id', None)
        super().__init__(*args, **kwargs)

    def clean_Correo(self):
        correo = self.cleaned_data['Correo']
        
        if self.db:
            
            usuarios_con_correo = self.db.child("usuarios").order_by_child("Correo").equal_to(correo).get()
            if usuarios_con_correo.each():
                usuario_existe = usuarios_con_correo.each()[0]
                if usuario_existe.val().get("ID_Usuario") != self.usuario_id:
                    raise forms.ValidationError("El correo ya está en uso por otro usuario.")
        
        return correo