"""User deletion contracts, including Django collector effects and rollback."""

import hashlib
import uuid
from datetime import datetime, time, timezone
from unittest.mock import patch


def run(seed, go_request, snapshot):
    from django.db import connection
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType
    from django.contrib.sessions.models import Session
    from rest_framework.authtoken.models import Token
    from rest_framework.test import APIClient
    from allauth.account.models import EmailAddress, EmailConfirmation
    from allauth.socialaccount.models import SocialAccount, SocialToken
    from accounts.models import APIKey, User
    from agents.models import Agent, Note, PushToken
    from clients.models import Deployment
    from core.models import AIChatSession, AIChatMessage
    from knox.models import AuthToken
    from qdt_inventory.models import Asset, AssetEvent, AssetAttachment
    from qdt_reports.models import ReportConfiguration, ReportRun, ReportDelivery
    from alerts.models import MatrixChannel

    fixed = datetime(2024, 1, 2, tzinfo=timezone.utc)
    dependencies = [Token, EmailAddress, EmailConfirmation, SocialAccount, SocialToken,
                    Note, PushToken, Deployment, AIChatSession, AIChatMessage,
                    ReportConfiguration, ReportRun, ReportDelivery,
                    ReportDelivery.matrix_channels.through, AssetEvent, AssetAttachment,
                    User.groups.through, User.user_permissions.through, Session, Agent, Asset]

    def clean():
        # Assets protect sites; remove these fixtures before the shared seed.
        Asset.objects.all().delete()
        Agent.objects.all().delete()
        Group.objects.all().delete()
        Permission.objects.all().delete()
        MatrixChannel.objects.all().delete()
        Session.objects.all().delete()

    def prepare(rich=False):
        clean()
        seed()
        if not rich:
            return
        content_type, _ = ContentType.objects.get_or_create(app_label="accounts", model="user")
        for user_id in (2, 5):
            user = User.objects.get(pk=user_id)
            APIKey.objects.bulk_create([APIKey(id=100 + user_id, name=f"delete-{user_id}",
                                              key=str(user_id) * 32, user=user)])
            Token.objects.create(key=str(user_id) * 40, user=user)
            group = Group.objects.create(id=100 + user_id, name=f"delete-group-{user_id}")
            user.groups.add(group)
            perm = Permission.objects.create(id=100 + user_id, content_type=content_type,
                                             codename=f"delete-{user_id}", name="Delete fixture")
            user.user_permissions.add(perm)
            email = EmailAddress.objects.create(id=100 + user_id, user=user, email=f"{user_id}@example.test")
            EmailConfirmation.objects.create(id=100 + user_id, email_address=email, key=str(user_id), sent=fixed)
            social = SocialAccount.objects.create(id=100 + user_id, user=user, provider="openid_connect", uid=str(user_id))
            SocialToken.objects.create(id=100 + user_id, account=social, token="fixture")
            Agent.objects.bulk_create([Agent(id=100 + user_id, agent_id=f"delete-{user_id}", hostname="fixture", site_id=1)])
            Note.objects.create(id=100 + user_id, user=user, agent_id=100 + user_id, note="preserved")
            PushToken.objects.create(id=100 + user_id, user=user, token=f"push-{user_id}", platform="ios")
            Deployment.objects.create(id=100 + user_id, site_id=1, auth_token=AuthToken.objects.get(user=user), token_key="fixture")
            chat = AIChatSession.objects.create(id=uuid.UUID(int=user_id), user=user, title="private")
            AIChatMessage.objects.create(id=100 + user_id, session=chat, role="user", content="private")
            ReportConfiguration.objects.create(id=100 + user_id, owner=user, name="fixture")
            ReportRun.objects.create(id=100 + user_id, owner=user, client_id=1, name="fixture", client_name="Client", snapshot={})
            delivery = ReportDelivery.objects.create(id=100 + user_id, owner=user, name="fixture", configuration={},
                                                    recipients=[], frequency="daily", run_time=time(12), next_run_at=fixed)
            channel = MatrixChannel.objects.create(id=100 + user_id, name=f"delete-{user_id}")
            delivery.matrix_channels.add(channel)
            asset = Asset.objects.create(id=100 + user_id, site_id=1, inventory_number=f"delete-{user_id}", name="preserved")
            AssetEvent.objects.create(id=100 + user_id, asset=asset, actor=user, actor_name=user.username)
            AssetAttachment.objects.create(id=100 + user_id, asset=asset, uploaded_by=user,
                                           encrypted_name=b"name", encrypted_content=b"content", size=7)
            # Django sessions contain serialized user ids, not foreign keys: retain them.
            Session.objects.create(session_key=f"delete-{user_id}", session_data="preserved", expire_date=fixed)

    def state():
        result = snapshot()
        extra = {}
        for model in dependencies:
            rows = list(model.objects.order_by(model._meta.pk.name).values())
            for row in rows:
                for key, value in list(row.items()):
                    if isinstance(value, datetime):
                        row[key] = "timestamp"
                    elif isinstance(value, memoryview):
                        row[key] = bytes(value)
                # Auto-created M2M identities are not semantically observable.
                if model._meta.auto_created:
                    row.pop("id", None)
                if model is Deployment:
                    row.pop("uid")
                if model is SocialAccount and row["user_id"] == 7:
                    row["id"] = "seeded SSO account"
            extra[model._meta.db_table] = rows
        return result, extra

    cases = [("plain", 1, 3, False), ("cascades", 1, 2, True),
             ("sso", 1, 7, False), ("root protected", 5, 1, False),
             ("self root", 1, 1, False), ("self role admin", 5, 5, True),
             ("missing", 1, 999, False), ("reader denied", 2, 3, False),
             ("reader self denied", 2, 2, False), ("installer denied", 6, 3, False),
             ("inactive denied", 4, 3, False)]
    try:
        for name, actor, target, rich in cases:
            path = f"/accounts/{target}/users/"
            prepare(rich)
            client = APIClient()
            token = hashlib.sha256(f"contract-user-{actor}".encode()).hexdigest()
            client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
            with patch("accounts.views.sync_mesh_perms_task.delay") as dispatch:
                reference = client.delete(path)
            expected = (reference.status_code, reference.json())
            expected_state = state()
            prepare(rich)
            actual = go_request("DELETE", path, user_id=actor)
            assert actual == expected, (name, expected, actual)
            assert state() == expected_state, (name, "deletion effects differ", state(), expected_state)
            with connection.cursor() as cursor:
                cursor.execute("SELECT generation FROM go_mesh_sync")
                assert cursor.fetchall() == ([(1,)] if dispatch.called else []), name
            print(f"PASS user delete {name}")

        # A failure after cascading deletes must also restore retained references,
        # the account, its audit entry and the durable Mesh dispatch.
        for table, operation in [("go_mesh_sync", "INSERT"), ("logs_auditlog", "INSERT"),
                                 ("accounts_user", "DELETE")]:
            prepare(True)
            assert go_request("GET", "/core/version/")[0] == 200
            before = state()
            with connection.cursor() as cursor:
                cursor.execute("CREATE FUNCTION reject_user_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'contract rejection'; END $$")
                cursor.execute(f"CREATE TRIGGER reject_user_delete BEFORE {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION reject_user_delete()")
            try:
                assert go_request("DELETE", "/accounts/2/users/")[0] == 500
                assert state() == before, (table, "deletion did not roll back")
                with connection.cursor() as cursor:
                    cursor.execute("SELECT count(*) FROM go_mesh_sync")
                    assert cursor.fetchone()[0] == 0
            finally:
                with connection.cursor() as cursor:
                    cursor.execute(f"DROP TRIGGER reject_user_delete ON {table}")
                    cursor.execute("DROP FUNCTION reject_user_delete()")
        print("PASS user delete cascade/audit/outbox rollback")
    finally:
        clean()
        seed()
    return len(cases)
