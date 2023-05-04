from django.contrib import admin
from .models import Reset, User

admin.site.register((Reset,User))