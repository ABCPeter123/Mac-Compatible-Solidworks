import copy
import unittest
from scripts.netfx481_webview2_restart_gate import eligible, operational


def evidence():
    live = dict(probe_result="COMPLETE", runtime_discovery="VERSION_FOUND",
                environment_creation="READY", controller_creation="READY",
                controller_created=True, environment_hresult="0X00000000",
                controller_hresult="0X00000000")
    initial = dict(schema=1, scope="OFFICIAL_INSTALLER_TRIAL_NOT_SOLIDWORKS",
                   installer_execution="TIMEOUT", installer_exit_code=None,
                   installer_sha256_verified=True, runtime_installation_confirmed=False,
                   browser_controller_confirmed=True, controller_transition="BECAME_READY",
                   before=dict(probe_result="COMPLETE", runtime_discovery="NOT_DISCOVERED"),
                   after=live)
    restart = dict(schema=1, setup_termination="TIMEOUT",
                   installer_transaction_confirmed=False, session_quiesced=True,
                   restart="COMPLETED", live=copy.deepcopy(live), operational_ready=True,
                   solidworks_compatibility="NOT_DEMONSTRATED")
    return initial, restart


class RestartGateTests(unittest.TestCase):
    def test_exact_timeout_can_be_operational_but_not_transaction_success(self):
        initial, restart = evidence()
        self.assertTrue(eligible(initial))
        self.assertTrue(operational(initial, restart))
        self.assertFalse(initial["runtime_installation_confirmed"])

    def test_reject_failure_or_unverified_shutdown_restart_or_controller(self):
        for key, value in (("session_quiesced", False), ("restart", "TIMED_OUT"),
                           ("installer_transaction_confirmed", True),
                           ("operational_ready", False), ("live", None)):
            initial, restart = evidence()
            restart[key] = value
            self.assertFalse(operational(initial, restart))
        initial, restart = evidence()
        restart["live"]["controller_hresult"] = "0X80070002"
        self.assertFalse(operational(initial, restart))
        initial, restart = evidence()
        initial["installer_execution"] = "EXIT_NONZERO"
        self.assertFalse(operational(initial, restart))

    def test_zero_exit_still_requires_new_controller(self):
        initial, restart = evidence()
        initial.update(installer_execution="EXIT_ZERO", installer_exit_code=0,
                       runtime_installation_confirmed=True)
        restart.update(setup_termination="EXIT_ZERO", installer_transaction_confirmed=True)
        self.assertTrue(operational(initial, restart))
        restart["live"]["controller_created"] = False
        self.assertFalse(operational(initial, restart))
