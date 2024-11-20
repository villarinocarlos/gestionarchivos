"""
URL configuration for gestion_archivos project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.ciom/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from archivos import views
from archivos.views import editar_archivo
from archivos.views import admin_page
from archivos.views import logout_view
from archivos.views import login_view
from archivos.views import reportes_auditoria
from archivos.views import reportar_archivos


urlpatterns = [
    path('login/', login_view, name='login'),
    path('', views.pagina_principal, name='pagina_principal'),
    path('archivos/', views.lista_archivos, name='lista_archivos'),
    path('subir/', views.subir_archivo, name='subir_archivo'),
    path('ver/<str:archivo_id>/', views.ver_archivo, name='ver_archivo'),
    path('borrar/<str:archivo_id>/', views.borrar_archivo, name='borrar_archivo'),
    path('editar/<str:archivo_id>/', editar_archivo, name='editar_archivo'),  
    path('admin_page/', views.admin_page, name='admin_page'),
    path('crear_usuario/', views.crear_usuario, name='crear_usuario'),
    path('logout/', logout_view, name='logout'),
    path('admin/editar_usuario/<int:usuario_id>/', views.editar_usuario, name='editar_usuario'),
    path('admin/eliminar_usuario/<int:usuario_id>/', views.eliminar_usuario, name='eliminar_usuario'),
    path('admin/logs/',views.ver_logs, name='ver_logs'),
    path('reportes/', reportes_auditoria, name='reportes_auditoria'),
    path('reportar/', views.reportar_archivos, name='reportar_archivos'),  # Ruta para mostrar el formulario
    path('generar_informe_pdf/', views.generar_informe_pdf, name='generar_informe_pdf'),  # Ruta para generar el PDF
    # Otras URLs...
]