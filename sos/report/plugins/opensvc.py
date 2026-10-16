# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import os

from sos.report.plugins import Plugin, IndependentPlugin


class Opensvc(Plugin, IndependentPlugin):

    short_desc = 'OpenSVC cluster and services (config and state collection)'
    plugin_name = 'opensvc'
    profiles = ('cluster', 'services', 'system')
    packages = ('opensvc',)

    def find_om(self):
        """ Return the path of the om executable, or None """
        for path in os.environ.get("PATH", "").split(os.path.pathsep):
            om_path = self.path_join(path, "om")
            if os.access(om_path, os.X_OK):
                return om_path
        return None

    def detect_om_version(self):
        """ Detect om version: ELF binary => v3, script => v2 """
        om_path = self.find_om()
        if om_path is None:
            self._log_debug("om command not found")
            return None
        try:
            with open(om_path, 'rb') as om_file:
                magic = om_file.read(4)
        except OSError as error:
            self._log_debug(f"Error while reading {om_path}: {error}")
            return None
        if magic == b'\x7fELF':
            return 3
        if magic.startswith(b'#!'):
            return 2
        self._log_debug(f"Unable to detect om version from {om_path}")
        return None

    def list_objects(self, kind, om_version):
        """ Return the names of the objects of the given kind """
        if om_version == 3:
            header = "OBJECT"
            cmd = (f"om {kind} ls --color=no "
                   f"--output tab={header}:meta.object")
        else:
            header = None
            cmd = f"om {kind} ls --color=no"
        res = self.collect_cmd_output(cmd, suggest_filename=f"{kind}-ls")
        if res['status'] != 0:
            return []
        objs = []
        for line in res['output'].splitlines():
            line = line.strip()
            if not line or line == header:
                continue
            objs.append(line)
        return objs

    @staticmethod
    def split_object_path(path, kind):
        """ Split an object path [[<ns>/]<kind>/]<name> into its
        namespace, kind and name """
        parts = path.split('/')
        name = parts[-1]
        kind = parts[-2] if len(parts) > 1 else kind
        namespace = parts[-3] if len(parts) > 2 else "root"
        return namespace, kind, name

    def add_object_cmd(self, kind, obj, cmd, suffix):
        """ Run an om command on an object, saved as
        <kind>_<suffix>/<ns>/<kind>/<name>-<suffix> """
        namespace, obj_kind, name = self.split_object_path(obj, kind)
        self.add_cmd_output(
            f"om {obj} {cmd}",
            suggest_filename=f"{name}-{suffix}",
            subdir=f"{kind}_{suffix}/{namespace}/{obj_kind}"
        )

    def get_status(self, kind, om_version):
        """ Get the status of the objects of the given kind """
        action = "instance status" if om_version == 3 else "print status"
        for obj in self.list_objects(kind, om_version):
            self.add_object_cmd(kind, obj, f"{action} --color=no", "status")

    def get_config_v3(self, kind):
        """ Get the config of the objects of the given kind, secrets
        redacted """
        for obj in self.list_objects(kind, 3):
            self.add_object_cmd(
                kind, obj, "config show --color=no --redact-secrets", "config"
            )

    def setup_v3(self):
        self.add_copy_spec([
            "/var/lib/opensvc/*.stack*",
            "/var/lib/opensvc/cni/net.d/*.conf",
        ])

        self.add_cmd_output("om --version", suggest_filename="version")

        # saved as <cmd>-<fmt>, or <cmd> if run with a single format or
        # without --output (no format), the "**" selector left out
        fmts = ("auto", "json", "flat")
        cmds = [
            ("pool list", fmts),
            ("net list", fmts),
            ("mon", fmts),
            ("daemon dns dump", fmts),
            ("daemon relay status", fmts),
            ("daemon status", fmts),
            ("daemon ps", fmts),
            ("array list", fmts),
            ("daemon hb status", ("auto",)),
            ("daemon exec list", fmts),
            ("daemon orchestration list", fmts),
            ("daemon session list", fmts),
            ("daemon log", ()),
            ("node list", fmts),
            ("node drivers", fmts),
            ("node schedule list", fmts),
            ("node capabilities list", fmts),
            ("node config validate", fmts),
            ("node relay list", fmts),
            ("node metrics", ()),
            ("cluster config validate", fmts),
            ("network ip list", fmts),
            ("pool volume list", fmts),
            ("** config validate", fmts),
            ("** instance list", fmts),
            ("** instance device list", fmts),
            ("** schedule list", fmts),
        ]
        for cmd, cmd_fmts in cmds:
            name = cmd.replace('** ', '').replace(' ', '-')
            if not cmd_fmts:
                self.add_cmd_output(f"om {cmd} --color=no",
                                    suggest_filename=name)
            for fmt in cmd_fmts:
                self.add_cmd_output(
                    f"om {cmd} --color=no --output {fmt}",
                    suggest_filename=(
                        f"{name}-{fmt}" if len(cmd_fmts) > 1 else name
                    )
                )

        self.add_dir_listing("/run/opensvc", recursive=True,
                             suggest_filename="ls-run-opensvc")
        self.get_config_v3("sec")
        self.get_config_v3("usr")

    def setup_v2(self):
        cmds = [
            ("pool status --verbose", "pool-status"),
            ("net status --verbose", "net-status"),
            ("mon", "mon"),
            ("daemon dns dump", "daemon-dns-dump"),
            ("daemon relay status", "daemon-relay-status"),
            ("daemon status --format flat_json", "daemon-status"),
        ]
        for cmd, name in cmds:
            self.add_cmd_output(f"om {cmd} --color=no",
                                suggest_filename=name)

    def setup(self):
        # sec and usr objects configs hold secrets in clear text.
        # Globbed forbidden paths must match the files, not only their
        # parent directory.
        self.add_forbidden_path([
            "/etc/opensvc/sec",
            "/etc/opensvc/usr",
            "/etc/opensvc/namespaces/*/sec/*",
            "/etc/opensvc/namespaces/*/usr/*",
            "/var/lib/opensvc/sec",
            "/var/lib/opensvc/usr",
            "/var/lib/opensvc/namespaces/*/sec/*",
            "/var/lib/opensvc/namespaces/*/usr/*",
        ])

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
            "/var/lib/opensvc/svc/*",
            "/var/lib/opensvc/vol/*",
            "/var/lib/opensvc/nscfg/*",
        ])
        self.add_dir_listing('/var/lib/opensvc', recursive=True,
                             suggest_filename="ls-var-lib-opensvc")

        om_version = self.detect_om_version()
        if om_version == 3:
            self.setup_v3()
        elif om_version == 2:
            self.setup_v2()

        if om_version is not None:
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

        cluster_regex = r"(\s*secret =\s*)\S+"
        self.do_file_sub(
            "/etc/opensvc/cluster.conf",
            cluster_regex,
            r"\1****************************"
        )

        node_regex = r"(\s*uuid =\s*)\S+"
        self.do_file_sub(
            "/etc/opensvc/node.conf",
            node_regex,
            r"\1****************************"
        )


# vim: set et ts=4 sw=4 :
