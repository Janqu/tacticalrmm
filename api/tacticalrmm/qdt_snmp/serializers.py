import re

from rest_framework import serializers

from core.serializers import mask_token

from .models import SnmpDevice, SnmpReading

OID_RE = re.compile(r"^\d+(\.\d+)+$")
ALLOWED_MAP_KEYS = {"oid", "max_oid", "scale"}
ALLOWED_THRESHOLD_KEYS = {"warning", "error", "direction"}


def validate_thresholds(value):
    """A typo here means an alert that never fires, which nobody notices."""
    if not value:
        return {}
    if not isinstance(value, dict):
        raise serializers.ValidationError("thresholds must be an object")

    for metric, spec in value.items():
        if not isinstance(spec, dict):
            raise serializers.ValidationError(f"{metric}: entry must be an object")
        unknown = set(spec) - ALLOWED_THRESHOLD_KEYS
        if unknown:
            raise serializers.ValidationError(
                f"{metric}: unknown keys {sorted(unknown)}, allowed are {sorted(ALLOWED_THRESHOLD_KEYS)}"
            )
        if not {"warning", "error"} & set(spec):
            raise serializers.ValidationError(f"{metric}: needs a warning or an error level")
        for level in ("warning", "error"):
            if level in spec and not isinstance(spec[level], (int, float)):
                raise serializers.ValidationError(f"{metric}: {level} must be a number")
        if spec.get("direction", "below") not in ("below", "above"):
            raise serializers.ValidationError(f"{metric}: direction must be below or above")

    return value


def validate_metric_map(value):
    """Garbage here would silently produce wrong readings, so reject it at the door."""
    if not value:
        return {}
    if not isinstance(value, dict):
        raise serializers.ValidationError("metric_map must be an object")

    for metric, spec in value.items():
        if not isinstance(spec, dict):
            raise serializers.ValidationError(f"{metric}: entry must be an object")

        unknown = set(spec) - ALLOWED_MAP_KEYS
        if unknown:
            raise serializers.ValidationError(
                f"{metric}: unknown keys {sorted(unknown)}, allowed are {sorted(ALLOWED_MAP_KEYS)}"
            )
        for key in ("oid", "max_oid"):
            if key in spec and not OID_RE.match(str(spec[key])):
                raise serializers.ValidationError(f"{metric}: {key} is not a dotted OID")
        if "oid" not in spec:
            raise serializers.ValidationError(f"{metric}: oid is required")
        if "scale" in spec and not isinstance(spec["scale"], (int, float)):
            raise serializers.ValidationError(f"{metric}: scale must be a number")

    return value


class SnmpDeviceSerializer(serializers.ModelSerializer):
    """Dashboard-facing. The community string is masked on read, same convention as
    the AI provider tokens in CoreSettings."""

    status = serializers.ReadOnlyField()
    site_name = serializers.ReadOnlyField(source="site.name")
    client_name = serializers.ReadOnlyField(source="site.client.name")

    class Meta:
        model = SnmpDevice
        fields = (
            "id",
            "site",
            "site_name",
            "client_name",
            "name",
            "device_type",
            "ip",
            "port",
            "community",
            "enabled",
            "description",
            "offline_minutes",
            "metric_map",
            "thresholds",
            "email_alerts",
            "model_name",
            "serial",
            "last_seen",
            "last_error",
            "status",
        )
        read_only_fields = ("model_name", "serial", "last_seen", "last_error")

    def validate_metric_map(self, value):
        return validate_metric_map(value)

    def validate_thresholds(self, value):
        return validate_thresholds(value)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret["community"] = mask_token(instance.community)
        return ret

    def validate_community(self, value):
        # the value comes back masked, so an unchanged one means "keep what is stored"
        if self.instance is not None and value and "•" in value:
            return self.instance.community
        return value


class SnmpProbeDeviceSerializer(serializers.ModelSerializer):
    """Probe-facing. Deliberately returns the community in the clear — the probe needs
    it to talk SNMP. Only reachable with a key scoped to the site."""

    class Meta:
        model = SnmpDevice
        fields = ("id", "name", "device_type", "ip", "port", "community", "metric_map")


class SnmpReadingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SnmpReading
        fields = ("metric", "value", "text", "timestamp")


class SnmpIngestSerializer(serializers.Serializer):
    """What a probe posts back after polling. Unknown device ids are rejected rather
    than ignored, so a misconfigured probe fails loudly."""

    id = serializers.IntegerField()
    reachable = serializers.BooleanField()
    model_name = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, max_length=255
    )
    serial = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, max_length=255
    )
    error = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, max_length=2000
    )
    metrics = serializers.DictField(
        child=serializers.FloatField(allow_null=True), required=False
    )
