from unittest.mock import patch

from model_bakery import baker

from tacticalrmm.test import TacticalTestCase


class TestClientHealthReportScope(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.customer = baker.make("clients.Client")
        self.other_customer = baker.make("clients.Client")
        self.allowed_site = baker.make("clients.Site", client=self.customer)
        self.hidden_site = baker.make("clients.Site", client=self.customer)
        self.foreign_site = baker.make("clients.Site", client=self.other_customer)
        self.agents = [
            baker.make_recipe("agents.online_agent", site=site, hostname=name)
            for site, name in (
                (self.allowed_site, "allowed"),
                (self.hidden_site, "hidden"),
                (self.foreign_site, "foreign"),
            )
        ]
        for agent in self.agents:
            baker.make(
                "alerts.Alert", agent=agent, resolved=False, message=agent.hostname
            )
        # These helpers do not enforce scope; stub only their expensive summaries.
        for helper, value in (
            ("_agent_patch_summary", {"pending": 0, "installed_recently": 0}),
            ("_agent_check_summary", {"failing": 0}),
        ):
            mock = patch(f"qdt_reports.views.{helper}", return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def report(self, customer=None):
        customer = customer or self.customer
        return self.client.get(f"/qdt_reports/client/{customer.pk}/health/")

    def test_site_only_role_sees_only_allowed_agents_alerts_and_totals(self):
        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_sites.add(self.allowed_site)
        self.client.force_authenticate(user=user)
        response = self.report()
        self.assertEqual(response.status_code, 200)
        self.assertEqual([a["hostname"] for a in response.data["agents"]], ["allowed"])
        self.assertEqual([a["message"] for a in response.data["alerts"]], ["allowed"])
        self.assertEqual(response.data["summary"]["total_agents"], 1)
        self.assertEqual(response.data["summary"]["open_alerts"], 1)
        self.assertEqual(self.report(self.other_customer).status_code, 404)

    def test_client_scope_and_site_scope_form_a_union(self):
        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_clients.add(self.other_customer)
        user.role.can_view_sites.add(self.allowed_site)
        self.client.force_authenticate(user=user)
        self.assertEqual(
            [a["hostname"] for a in self.report().data["agents"]], ["allowed"]
        )
        self.assertEqual(
            [a["hostname"] for a in self.report(self.other_customer).data["agents"]],
            ["foreign"],
        )

    def test_client_role_can_see_all_sites_of_its_customer(self):
        user = self.create_user_with_roles(["can_list_agents"])
        user.role.can_view_clients.add(self.customer)
        self.client.force_authenticate(user=user)
        self.assertEqual(self.report().data["summary"]["total_agents"], 2)
        self.assertEqual(self.report(self.other_customer).status_code, 404)

    def test_admin_keeps_complete_customer_report(self):
        self.assertEqual(self.report().data["summary"]["total_agents"], 2)
        self.assertEqual(
            self.report(self.other_customer).data["summary"]["total_agents"], 1
        )

    def test_role_without_agent_read_permission_is_denied(self):
        user = self.create_user_with_roles(["can_list_sites"])
        self.client.force_authenticate(user=user)
        self.assertEqual(self.report().status_code, 403)

    def test_roleless_user_and_anonymous_request_are_denied(self):
        user = baker.make("accounts.User", is_active=True, role=None)
        self.client.force_authenticate(user=user)
        self.assertEqual(self.report().status_code, 403)
        self.client.force_authenticate(user=None)
        self.assertEqual(self.report().status_code, 401)

    def test_empty_permitted_site_does_not_reveal_other_sites(self):
        user = self.create_user_with_roles(["can_list_agents"])
        empty_site = baker.make("clients.Site", client=self.customer)
        user.role.can_view_sites.add(empty_site)
        self.client.force_authenticate(user=user)
        response = self.report()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["agents"], [])
        self.assertEqual(response.data["alerts"], [])
        self.assertEqual(response.data["summary"]["total_agents"], 0)
