import secrets

from django.db import migrations, models
import django.db.models.deletion
import qdt_snmp.models


def migrate_pollers(apps, schema_editor):
    alias = schema_editor.connection.alias
    Credential = apps.get_model("qdt_snmp", "SnmpProbeCredential")
    Task = apps.get_model("autotasks", "AutomatedTask")
    APIKey = apps.get_model("accounts", "APIKey")
    KeyStore = apps.get_model("core", "GlobalKVStore")
    Script = apps.get_model("scripts", "Script")

    script_ids = set(Script.objects.using(alias).filter(
        name="QDT SNMP Poller", category="QDT"
    ).values_list("pk", flat=True))

    for task in Task.objects.using(alias).filter(
        name="QDT SNMP Poller", agent__isnull=False
    ).select_related("agent").order_by("pk"):
        changed = False
        for action in task.actions or []:
            if action.get("type") != "script" or action.get("script") not in script_ids:
                continue
            args = list(action.get("script_args") or [])
            if "--api-key" not in args:
                continue
            index = args.index("--api-key") + 1
            if index >= len(args):
                continue
            args[index] = "{{agent.snmp_probe_key}}"
            action["script_args"] = args
            changed = True
        if changed:
            Credential.objects.using(alias).get_or_create(
                site_id=task.agent.site_id,
                defaults={"agent_id": task.agent_id, "key": secrets.token_hex(32)},
            )
            task.save(using=alias, update_fields=["actions"])

    # The old key may have belonged to an administrator on earlier installations.
    # Revoke both the named key and the exact key distributed via the global store.
    old_values = list(KeyStore.objects.using(alias).filter(
        name="snmp_api_key"
    ).values_list("value", flat=True))
    APIKey.objects.using(alias).filter(
        models.Q(name="snmp-probe") | models.Q(key__in=old_values)
    ).delete()
    KeyStore.objects.using(alias).filter(name="snmp_api_key").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("qdt_snmp", "0003_snmpdevice_email_alerts_snmpdevice_thresholds_and_more"),
        ("agents", "0062_agent_default_shell_agent_default_shell_custom"),
        ("autotasks", "0041_automatedtask_task_supported_platforms_and_more"),
        ("accounts", "0042_copy_mesh_permission_to_terminal"),
        ("core", "0055_aichatsession_aichatmessage"),
    ]

    operations = [
        migrations.CreateModel(
            name="SnmpProbeCredential",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(default=qdt_snmp.models.new_probe_key, editable=False, max_length=64, unique=True)),
                ("agent", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="agents.agent")),
                ("site", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to="clients.site")),
            ],
        ),
        # Deliberately irreversible: a rollback must not restore a shared credential.
        migrations.RunPython(migrate_pollers),
    ]
