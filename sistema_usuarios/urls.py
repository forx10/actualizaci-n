"""
URL configuration for sistema_usuarios project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from usuarios import views as usuarios_views
from django.contrib.auth import views as auth_views


urlpatterns = [
    # Ruta de panel de administración
    path('admin/', admin.site.urls),

    # Rutas de inicio de sesión y registro como de dashboard de la página (inicio)
    path('registro/', usuarios_views.registro, name='registro'),
    path('login/', usuarios_views.iniciar_sesion, name='login'),
    path('inicio/', usuarios_views.inicio, name='inicio'),  # NUEVA RUTA

    # Gestión de usuarios (solo para administradores y superusuario)
    path('dashboard-admin/', usuarios_views.dashboard_admin, name='dashboard_admin'),
    path('admin_dashboard_limited/', usuarios_views.admin_dashboard_limited, name='admin_dashboard_limited'),
    path('gestion-usuarios/', usuarios_views.gestion_usuarios, name='gestion_usuarios'),
    path('agregar-usuario/', usuarios_views.agregar_usuario, name='agregar_usuario'),
    path('editar-usuario/<int:user_id>/', usuarios_views.editar_usuario, name='editar_usuario'),
    path('eliminar-usuario/<int:user_id>/', usuarios_views.eliminar_usuario, name='eliminar_usuario'),


    # Recuperación de contraseña
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='usuarios/password_reset.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='usuarios/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='usuarios/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='usuarios/password_reset_complete.html'), name='password_reset_complete'),

    # Actividades de fragaria
    # path('siembra/', usuarios_views.seleccion_siembra, name='siembra'),
    path('plantacion/', usuarios_views.plantacion, name='plantacion'),  # Mostrar las plantaciones
    path('plantaciones/', usuarios_views.listar_plantaciones, name='plantaciones'),
    path('registrar-plantacion/', usuarios_views.registrar_plantacion, name='registrar_plantacion'),  # Formulario de registro de plantación
    path('registrar-actividad/', usuarios_views.registrar_actividad, name='registrar_actividad'),
    path('actividades/', usuarios_views.lista_actividades, name='lista_actividades'),
    path('actividades/<int:actividad_id>/registrar-estado/', usuarios_views.registrar_estado_actividad, name='registrar_estado_actividad'),
    path('cronograma/', usuarios_views.cronograma, name='cronograma'),  # Añadimos la ruta para el cronograma
    
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),

    # URL para informes (si es necesaria)
    path('informes/', usuarios_views.informes, name='informes'),
    path('editar-plantacion/<int:id>/', usuarios_views.editar_plantacion, name='editar_plantacion'),
    path('eliminar-plantacion/<int:id>/', usuarios_views.eliminar_plantacion, name='eliminar_plantacion')
    


]


