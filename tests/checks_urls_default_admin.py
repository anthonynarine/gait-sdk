"""URLconf for the check-pack tests: the admin at the default /admin/."""

from django.contrib import admin
from django.urls import path

urlpatterns = [path("admin/", admin.site.urls)]
