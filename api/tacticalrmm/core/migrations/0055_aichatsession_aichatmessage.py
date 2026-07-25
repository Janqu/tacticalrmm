# Generated manually to add AI chat session persistence.

import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0054_coresettings_ai_provider_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="AIChatSession",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("title", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=models.CASCADE,
                        related_name="ai_chat_sessions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-updated_at"],
            },
        ),
        migrations.CreateModel(
            name="AIChatMessage",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "role",
                    models.CharField(
                        choices=[
                            ("system", "System"),
                            ("user", "User"),
                            ("assistant", "Assistant"),
                        ],
                        max_length=20,
                    ),
                ),
                ("content", models.TextField()),
                ("tool_calls", models.JSONField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "session",
                    models.ForeignKey(
                        on_delete=models.CASCADE,
                        related_name="messages",
                        to="core.aichatsession",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
    ]
