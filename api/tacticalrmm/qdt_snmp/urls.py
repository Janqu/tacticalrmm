from django.urls import path

from . import views

urlpatterns = [
    path("devices/", views.GetAddSnmpDevices.as_view()),
    path("devices/<int:pk>/", views.GetUpdateDeleteSnmpDevice.as_view()),
    path("devices/<int:pk>/readings/", views.SnmpDeviceReadings.as_view()),
    path("discover/", views.DiscoverSnmpDevice.as_view()),
    path("sites/<int:site_id>/probe/", views.SiteProbe.as_view()),
    path("latest/", views.SnmpLatestReadings.as_view()),
    path("alerts/", views.SnmpOpenAlerts.as_view()),
    path("probe/<agent:agent_id>/devices/", views.ProbeDevices.as_view()),
]
