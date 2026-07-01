# Generated for QDT customization

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0053_coresettings_terminal_mode"),
    ]

    operations = [
        migrations.AddField(
            model_name="coresettings",
            name="ai_provider",
            field=models.CharField(
                choices=[("openai", "OpenAI"), ("minimax", "MiniMax")],
                default="openai",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="coresettings",
            name="minimax_token",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="coresettings",
            name="minimax_model",
            field=models.CharField(blank=True, default="MiniMax-M3", max_length=255),
        ),
    ]
