# Generated manually to add AI_CHAT_TOOL to AuditLog.action choices.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("logs", "0025_alter_auditlog_id_alter_debuglog_id_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="auditlog",
            name="action",
            field=models.CharField(
                choices=[
                    ("login", "User Login"),
                    ("failed_login", "Failed User Login"),
                    ("delete", "Delete Object"),
                    ("modify", "Modify Object"),
                    ("add", "Add Object"),
                    ("view", "View Object"),
                    ("check_run", "Check Run"),
                    ("task_run", "Task Run"),
                    ("agent_install", "Agent Install"),
                    ("remote_session", "Remote Session"),
                    ("execute_script", "Execute Script"),
                    ("execute_command", "Execute Command"),
                    ("bulk_action", "Bulk Action"),
                    ("url_action", "URL Action"),
                    ("ai_chat_tool", "AI Chat Tool"),
                ],
                max_length=100,
            ),
        ),
    ]
