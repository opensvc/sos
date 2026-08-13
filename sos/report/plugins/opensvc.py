# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin


class Opensvc(Plugin, IndependentPlugin):

    short_desc = 'OpenSVC cluster and services (config and state collection)'
    plugin_name = 'opensvc'
    profiles = ('cluster', 'services', 'system')
    packages = ('opensvc',)

    def detect_om_version(self):
        """Detect om version: non-zero exit -> treat as v2, zero -> v3"""
        om_path = self.exec_cmd("which om")
        if om_path['status'] != 0:
            self._log_debug("om command not found")
            return None
        res = self.exec_cmd(f"file -bL {om_path['output'].strip()}")
        if res['status'] != 0:
            self._log_debug(f"file command failed for {om_path['output'].strip()}")
            return None
        return 3 if "ELF" in res['output'] else 2 if "script" in res['output'] else None

    def get_status(self, kind, om_version):
        """ Get the status of opensvc management service """
        object_tab = "OBJECT"
        output_flag = f"--output tab={object_tab}:meta.object" if om_version == 3 else ""
        get_objs = self.collect_cmd_output(f"om {kind} ls --color=no {output_flag}")
        dirname = kind + '_status'
        if get_objs['status'] == 0:
            for line in get_objs['output'].splitlines():
                if line == object_tab:
                    continue
                self.add_cmd_output(
                    f"om {line} {'instance' if om_version == 3 else 'print'} status --color=no",
                    subdir=dirname
                )

    def setup(self):
        om_version = self.detect_om_version()
        if om_version is None:
            return
        self.add_copy_spec([
            "/etc/opensvc/*",
            "/var/log/opensvc/*",
            "/etc/conf.d/opensvc",
            "/etc/default/opensvc",
            "/etc/sysconfig/opensvc",
            "/var/lib/opensvc/*.json",
            "/var/lib/opensvc/list.*",
            "/var/lib/opensvc/ccfg",
            "/var/lib/opensvc/cfg",
            "/var/lib/opensvc/certs/ca_certificates",
            "/var/lib/opensvc/certs/certificate_chain",
            "/var/lib/opensvc/compliance/*",
            "/var/lib/opensvc/namespaces/*",
            "/var/lib/opensvc/node/*",
            "/var/lib/opensvc/sec/*",
            "/var/lib/opensvc/svc/*",
            "/var/lib/opensvc/usr/*",
            "/var/lib/opensvc/vol/*",
        ])

        if om_version == 3:
            self.add_copy_spec([
                "/var/lib/opensvc/*.stack",
                "/run/opensvc/*"
            ])

            self.add_cmd_output([
                "om pool list --output json --color=no",
                "om pool list --color=no",
                "om net list --output json --color=no",
                "om net list --color=no",
                "om mon --color=no",
                "om mon --output json --color=no",
                "om daemon dns dump --color=no",
                "om daemon dns dump --output json --color=no",
                "om daemon relay status --color=no",
                "om daemon relay status --output json --color=no",
                "om daemon status --color=no",
                "om daemon status --output json --color=no",
                "om daemon ps --color=no",
                "om daemon ps --output json --color=no",
                "om array list --color=no",
                "om array list --output json --color=no",
                "om daemon hb status --color=no",
                "om daemon hb status --output json --color=no",
            ])
        else:
            self.add_cmd_output([
                "om pool status --verbose --color=no",
                "om net status --verbose --color=no",
                "om mon --color=no",
                "om daemon dns dump --color=no",
                "om daemon relay status --color=no",
                "om daemon status --format flat_json --color=no"
            ])


        self.add_dir_listing('/var/lib/opensvc', recursive=True)
        self.get_status('vol', om_version)
        self.get_status('svc', om_version)
        pid_file = "/var/lib/opensvc/osvcd.pid"
        try:
            with open(pid_file, 'r', encoding='utf-8') as file:
                pid = file.read().strip()
                if not pid:
                    self._log_debug(f"{pid_file} is empty")
                    return
                if not pid.isdigit():
                    self._log_debug(f"Invalid PID in {pid_file}: {pid}")
                    return
                self.add_copy_spec(f"/proc/{pid}/task/*/status")
        except (IOError, FileNotFoundError, PermissionError) as error:
            self._log_debug(
                f"Error while reading PID file {pid_file}: {error}"
            )

    def postproc(self):
        # Example:
        #
        # [hb#2]
        # secret = mypassword
        # type = relay
        # timeout = 30
        #
        # to
        #
        # [hb#2]
        # secret = ****************************
        # type = relay
        # timeout = 30

        regexp = r"(\s*secret =\s*)\S+"
        self.do_file_sub(
            "/etc/opensvc/cluster.conf",
            regexp,
            r"\1****************************"
        )

# vim: set et ts=4 sw=4 :
