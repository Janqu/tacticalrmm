from django.urls import path

from . import views

urlpatterns = [
    path("devices/", views.GetAddSnmpDevices.as_view()),
    path("devices/<int:pk>/", views.GetUpdateDeleteSnmpDevice.as_view()),
    path("devices/<int:pk>/readings/", views.SnmpDeviceReadings.as_view()),
    path("discover/", views.DiscoverSnmpDevice.as_view()),
    path("probe/<agent:agent_id>/devices/", views.ProbeDevices.as_view()),
]
