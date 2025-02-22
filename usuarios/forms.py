from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from .models import Usuario
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth.forms import SetPasswordForm
from django import forms
from .models import Plantacion
from .models import Usuario  # Importa Usuario correctamente
from .models import Actividad, EstadoActividad


#Registro de formulario donde incluyen los datos de validacion para un registro cono nombre, apellido, correo, contraseñas etc..

class RegistroForm(UserCreationForm):
    class Meta:
        model = Usuario
        fields = ['email', 'first_name', 'last_name', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_staff = True  # Todos los usuarios son staff
        if commit:
            user.save()
        return user

#Registro de formulario donde incluyen los datos inicio de sesion


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    
#Cambio de datos si se ingresa via administrador    

class UsuarioForm(UserChangeForm):
    # Definimos los campos que quieres que los administradores puedan modificar
    class Meta:
        model = Usuario
        fields = ['first_name', 'last_name', 'email', 'is_active', 'is_staff']

    # Añadimos un campo para confirmar la contraseña si es necesario
    password = forms.CharField(label="Contraseña", widget=forms.PasswordInput, required=False)

    def clean_password(self):
        # Si el campo de la contraseña está vacío, no realizamos validaciones adicionales
        password = self.cleaned_data.get('password')
        if password:
            return password
        return None

class PlantacionForm(forms.ModelForm):
    class Meta:
        model = Plantacion
        fields = ['nombre', 'descripcion']
        
    # def save(self, commit=True):
    #     plantacion = super().save(commit=False)
    #     plantacion.usuario = self.instance.usuario  # Aquí asignas el usuario logueado
    #     if commit:
    #         plantacion.save()
    #     return plantacion
        
class ActividadForm(forms.ModelForm):
    class Meta:
        model = Actividad
        fields = ['nombre_actividad', 'tiempo_estimado', 'clima_requerido', 'fecha_vencimiento', 'fecha']

class EstadoActividadForm(forms.ModelForm):
    class Meta:
        model = EstadoActividad
        fields = ['estado', 'actividad']