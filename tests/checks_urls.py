"""URLconf for the check-pack tests: the admin lives at a non-default path."""

from django.contrib import admin
from django.urls import path

urlpatterns = [path("control-room/", admin.site.urls)]
