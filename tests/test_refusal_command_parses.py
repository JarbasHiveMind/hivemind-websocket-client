import re
import unittest

from click.testing import CliRunner

from hivemind_bus_client.scripts import hmclient_cmds


class TestRefusalCommandParses(unittest.TestCase):
    def test_printed_shared_command_is_accepted_by_the_cli(self):
        import hivemind_bus_client.identity as identity
        src = open(identity.__file__).read()
        commands = re.findall(r"'hivemind-client (--shared [a-z-]+) \.\.\.'", src)
        self.assertEqual(commands, ["--shared set-identity"] * 2)
        result = CliRunner().invoke(hmclient_cmds, commands[0].split() + ["--help"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("persist node identity", result.output)
