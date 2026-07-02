from django.urls import path

from . import views

urlpatterns = [
    path(
        "client/<int:client_id>/health/",
        views.ClientHealthReportView.as_view(),
    ),
]
