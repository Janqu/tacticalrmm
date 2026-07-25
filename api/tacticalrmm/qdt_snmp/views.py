import datetime as dt

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from tacticalrmm.helpers import notify_error
from tacticalrmm.permissions import _has_perm, _has_perm_on_agent, _has_perm_on_site

from .models import SnmpDevice, SnmpReading
from .serializers import (
    SnmpDeviceSerializer,
    SnmpIngestSerializer,
    SnmpProbeDeviceSerializer,
    SnmpReadingSerializer,
)

# devices are site infrastructure, so they ride on the site permissions rather than
# adding a Role field, which would mean a migration on the upstream accounts app
READ_PERM = "can_list_sites"
WRITE_PERM = "can_manage_sites"

MAX_READING_DAYS = 365


def _require(request, perm: str) -> None:
    if not _has_perm(request, perm):
        raise PermissionDenied()


def _require_site(request, site_id: int) -> None:
    if not _has_perm_on_site(request.user, site_id):
        raise PermissionDenied()


class GetAddSnmpDevices(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        _require(request, READ_PERM)

        devices = (
            SnmpDevice.objects.select_related("site__client")
            .filter_by_role(request.user)  # type: ignore
            .order_by("site__client__name", "site__name", "name")
        )

        if "site" in request.query_params:
            devices = devices.filter(site_id=request.query_params["site"])
        elif "client" in request.query_params:
            devices = devices.filter(site__client_id=request.query_params["client"])

        return Response(SnmpDeviceSerializer(devices, many=True).data)

    def post(self, request):
        _require(request, WRITE_PERM)

        serializer = SnmpDeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        _require_site(request, serializer.validated_data["site"].pk)
        device = serializer.save()

        return Response(SnmpDeviceSerializer(device).data)


class GetUpdateDeleteSnmpDevice(APIView):
    permission_classes = [IsAuthenticated]

    def _get(self, request, pk: int, perm: str) -> SnmpDevice:
        _require(request, perm)
        device = get_object_or_404(SnmpDevice.objects.select_related("site"), pk=pk)
        _require_site(request, device.site_id)
        return device

    def get(self, request, pk):
        return Response(
            SnmpDeviceSerializer(self._get(request, pk, READ_PERM)).data
        )

    def put(self, request, pk):
        device = self._get(request, pk, WRITE_PERM)
        serializer = SnmpDeviceSerializer(instance=device, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        # moving a device to a site the caller cannot see would be a way out of scope
        if "site" in serializer.validated_data:
            _require_site(request, serializer.validated_data["site"].pk)

        return Response(SnmpDeviceSerializer(serializer.save()).data)

    def delete(self, request, pk):
        self._get(request, pk, WRITE_PERM).delete()
        return Response("Device was removed")


class SnmpDeviceReadings(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        _require(request, READ_PERM)
        device = get_object_or_404(SnmpDevice, pk=pk)
        _require_site(request, device.site_id)

        try:
            days = min(int(request.query_params.get("days", 30)), MAX_READING_DAYS)
        except ValueError:
            return notify_error("days must be an integer")

        readings = device.readings.filter(
            timestamp__gte=djangotime.now() - dt.timedelta(days=days)
        )
        if "metric" in request.query_params:
            readings = readings.filter(metric=request.query_params["metric"])

        return Response(SnmpReadingSerializer(readings, many=True).data)


class ProbeDevices(APIView):
    """What the polling script on the probe agent asks for. Scoped to that agent's
    site, so a probe can never see or write devices at another customer."""

    permission_classes = [IsAuthenticated]

    def _site_id(self, request, agent_id: str) -> int:
        _require(request, READ_PERM)
        if not _has_perm_on_agent(request.user, agent_id):
            raise PermissionDenied()
        return get_object_or_404(Agent, agent_id=agent_id).site_id

    def get(self, request, agent_id):
        devices = SnmpDevice.objects.filter(
            site_id=self._site_id(request, agent_id), enabled=True
        )
        return Response(SnmpProbeDeviceSerializer(devices, many=True).data)

    def post(self, request, agent_id):
        site_id = self._site_id(request, agent_id)

        serializer = SnmpIngestSerializer(data=request.data, many=True)
        serializer.is_valid(raise_exception=True)

        by_id = {
            d.pk: d for d in SnmpDevice.objects.filter(site_id=site_id, enabled=True)
        }
        unknown = [r["id"] for r in serializer.validated_data if r["id"] not in by_id]
        if unknown:
            return notify_error(f"unknown or disabled device ids for this site: {unknown}")

        now = djangotime.now()
        readings = []

        with transaction.atomic():
            for result in serializer.validated_data:
                device = by_id[result["id"]]

                if result["reachable"]:
                    device.last_seen = now
                    device.last_error = None
                    for field in ("model_name", "serial"):
                        if result.get(field):
                            setattr(device, field, result[field])
                else:
                    device.last_error = result.get("error") or "unreachable"

                device.save(
                    update_fields=["last_seen", "last_error", "model_name", "serial"]
                )

                readings += [
                    SnmpReading(device=device, metric=metric, value=value)
                    for metric, value in (result.get("metrics") or {}).items()
                ]

            SnmpReading.objects.bulk_create(readings)

        return Response({"devices": len(serializer.validated_data), "readings": len(readings)})
