from rest_framework import serializers

from core.serializers import mask_token

from .models import SnmpDevice, SnmpReading


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
            "model_name",
            "serial",
            "last_seen",
            "last_error",
            "status",
        )
        read_only_fields = ("model_name", "serial", "last_seen", "last_error")

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
        fields = ("id", "name", "device_type", "ip", "port", "community")


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
