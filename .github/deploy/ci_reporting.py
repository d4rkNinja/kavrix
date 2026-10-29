"""Dependency-free, redacted GitHub Actions command logs and failure summaries."""
from collections import deque
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import uuid
from urllib.parse import quote, quote_plus

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SENSITIVE = re.compile(r"password|passwd|secret|token|credential|private.?key|(?:^|_)api.?key|(?:^|_)key$|(?:mongo|redis|database).*?(?:uri|url)|authorization", re.I)
LOCATION = re.compile(r"^(.+?\.(?:tsx?|jsx?|go|py|rs|vue|svelte))(?:(?:\((\d+),(\d+)\))|(?::(\d+)(?::(\d+))?)):\s*(.*)$")
ERROR = re.compile(r"\berror\b|\bfatal\b|\bexception\b|\bfailed\b|\bfail:\b|traceback|panic:", re.I)


def escape(value):
    return str(value).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


class CommandFailure(RuntimeError):
    def __init__(self, command, returncode):
        self.command = command
        self.returncode = returncode if returncode > 0 else 128 - returncode
        super().__init__(f"Command failed (exit {self.returncode}): {command}")


class Reporter:
    def __init__(self):
        self.secrets = set()
        self.context = {}
        self.tail = deque(maxlen=30)
        self.errors = deque(maxlen=60)
        self.diagnostics = []
        self.seen = set()
        self.command = ''
        self.failed_command = ''
        self.failure_details = []
        self.rollback = 'Not required'
        self.in_key = False
        self.add_env(os.environ)

    def add_env(self, values):
        for key, value in values.items():
            if isinstance(value, str) and value and SENSITIVE.search(key):
                # Short secrets are hidden too; avoid registering whitespace.
                self.secrets.add(value)
                self.secrets.add(value.strip().strip('\"\''))
                self.secrets.update((quote(value, safe=''), quote_plus(value)))
        self.secrets.discard('')

    def add_env_text(self, text):
        values = {}
        for line in text.splitlines():
            match = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
            if match:
                value = match[2].strip()
                try:
                    parsed = shlex.split(value, comments=True)
                    value = parsed[0] if len(parsed) == 1 else value
                except ValueError:
                    pass
                values[match[1]] = value
        self.add_env(values)

    def load_project(self, root):
        root = Path(root)
        ignored = {'.git', '.deploy', 'node_modules', '.next', 'dist', 'target', '.venv', 'logs', 'uploads', 'storage', 'data'}
        for directory, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ignored and not d.startswith('.venv')]
            for name in files:
                path = Path(directory) / name
                if name.startswith('.env') and not name.endswith(('.example', '.sample', '.template')):
                    try:
                        if path.stat().st_size <= 1024 * 1024:
                            self.add_env_text(path.read_text(errors='replace'))
                    except OSError:
                        # Files inaccessible to this runner are never read or streamed.
                        continue

    def configure(self, **context):
        self.context.update(context)
        if context.get('root'):
            self.load_project(context['root'])

    def clean(self, text):
        text = ANSI.sub('', str(text)).replace('\r', '')
        text = ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)
        for value in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(value, '[REDACTED]')
        text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+:[^/\s@]+@', r'\1[REDACTED]@', text)
        text = re.sub(r'(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_+./=-]+', r'\1 [REDACTED]', text)
        text = re.sub(r'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b', '[REDACTED]', text)
        text = re.sub(r'''(?i)((?:["']?)(?:password|passwd|api[_-]?key|secret|access[_-]?token)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)''', r'\1[REDACTED]', text)
        return text

    def line(self, raw, cwd):
        # Never echo multiline private keys, including their interior lines.
        if re.search(r'-----BEGIN .*PRIVATE KEY-----', raw):
            self.in_key = True
        if self.in_key:
            if re.search(r'-----END .*PRIVATE KEY-----', raw):
                self.in_key = False
            return '[REDACTED PRIVATE KEY]\n'
        text = self.clean(raw)
        marker = text.strip()
        if marker.startswith('CI_ROLLBACK: '):
            self.rollback = {'started': 'In progress', 'succeeded': 'Previous source and service restored',
                             'failed': 'FAILED; inspect the server service before retrying'}.get(
                                 marker.split(': ', 1)[1], 'Unknown')
        self.tail.append(text.rstrip())
        if ERROR.search(text):
            self.errors.append(text.rstrip())
        match = LOCATION.match(text.strip())
        if match:
            file, line1, col1, line2, col2, message = match.groups()
            path = Path(file)
            root = Path(self.context.get('root') or cwd or '.')
            if path.is_absolute():
                try:
                    path = path.relative_to(root)
                except ValueError:
                    return text
            if '..' not in path.parts and not path.is_absolute():
                diagnostic = (path.as_posix(), line1 or line2, col1 or col2 or '1', message)
                if diagnostic not in self.seen and len(self.diagnostics) < 50:
                    self.seen.add(diagnostic)
                    self.diagnostics.append(diagnostic)
        return text

    def annotate(self):
        if not os.environ.get('GITHUB_ACTIONS'):
            return
        for file, line, col, message in self.diagnostics:
            props = f"file={escape(file).replace(',', '%2C')},line={line},col={col}"
            print(f"::error {props}::{escape(self.clean(message))}", flush=True)

    def run(self, args, *, cwd=None, env=None, log=None, public=True):
        command = self.clean(shlex.join([str(a) for a in args]))
        self.command = command
        self.tail.clear()
        self.errors.clear()
        self.diagnostics.clear()
        self.seen.clear()
        token = uuid.uuid4().hex
        actions = bool(os.environ.get('GITHUB_ACTIONS'))
        if public:
            if actions:
                print('::group::' + escape(command), flush=True)
                print('::stop-commands::' + token, flush=True)
            else:
                print('$ ' + command, flush=True)
        child = None
        try:
            command_env = dict(os.environ if env is None else env)
            # The deployer deliberately strips CI variables from runtime commands.
            # Build descendants still need this marker so GitHub can clean them
            # up even when cancellation kills the parent before Python unwinds.
            # Never add it to private PM2/service activation commands.
            if public and os.environ.get('RUNNER_TRACKING_ID'):
                command_env['RUNNER_TRACKING_ID'] = os.environ['RUNNER_TRACKING_ID']
            child = subprocess.Popen(args, cwd=cwd, env=command_env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            assert child.stdout is not None
            with (Path(log).open('ab') if log else open(os.devnull, 'ab')) as protected:
                while True:
                    raw = child.stdout.readline(1024 * 1024 + 1)
                    if not raw:
                        break
                    protected.write(raw)
                    protected.flush()
                    if len(raw) > 1024 * 1024 and not raw.endswith(b'\n'):
                        # Do not split a long secret across published chunks.
                        while raw and not raw.endswith(b'\n'):
                            raw = child.stdout.readline(1024 * 1024)
                            protected.write(raw)
                        if public:
                            print('[Oversized output line retained only in the protected server log]', flush=True)
                        continue
                    if public:
                        text = self.line(raw.decode('utf-8', 'replace'), cwd)
                        print(text, end='' if text.endswith('\n') else '\n', flush=True)
                code = child.wait()
        except BaseException:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            raise
        finally:
            if public and actions:
                print('::' + token + '::', flush=True)
                print('::endgroup::', flush=True)
        if code:
            if not self.failed_command:
                self.failed_command = command
                self.failure_details = list(self.errors) + list(self.tail)
            self.annotate()
            raise CommandFailure(command, code)

    def finish(self, error=None):
        message = self.clean(str(error)) if error else ''
        if error:
            print('::error::' + escape(message), file=sys.stderr, flush=True)
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if not summary:
            return
        lines = ['## Deployment ' + ('failed' if error else 'passed'), '']
        for key in ('repository', 'branch', 'commit', 'mode', 'phase'):
            value = self.context.get(key)
            if value:
                lines.append(f"- {key.capitalize()}: `{self.clean(value).replace('`', '')}`")
        lines.append('- Rollback: ' + self.clean(self.rollback))
        if error:
            lines.extend(['', '**Failure:** ' + message.replace('`', ''), '',
                          ('**Failed command:** `' if self.failed_command else '**Last command:** `')
                          + self.clean(self.failed_command or self.command).replace('`', '') + '`'])
            excerpt = self.failure_details or list(self.errors) + list(self.tail)
            unique = list(dict.fromkeys(line for line in excerpt if line))
            if unique:
                # The complete sanitized command remains in the job log.
                content = '\n'.join(unique)[-24000:].replace('```', "'''")
                lines.extend(['', '### Error details', '', '```text', content, '```'])
        try:
            with open(summary, 'a', encoding='utf-8') as output:
                output.write('\n'.join(lines) + '\n')
        except OSError:
            print('::warning::Could not write the job summary; see the job log.', flush=True)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--cwd', default='.')
    parser.add_argument('--secret-root', action='append', default=[])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    opts = parser.parse_args()
    command = opts.command[1:] if opts.command[:1] == ['--'] else opts.command
    if not command:
        parser.error('a command is required')
    reporter = Reporter()
    reporter.configure(repository=os.environ.get('GITHUB_REPOSITORY', ''),
                       branch=os.environ.get('GITHUB_REF_NAME', ''),
                       commit=os.environ.get('GITHUB_SHA', ''), mode='build/deploy', root=opts.cwd)
    for root in opts.secret_root:
        reporter.load_project(root)
    try:
        reporter.run(command, cwd=opts.cwd, env=os.environ.copy())
    except Exception as error:
        reporter.finish(error)
        return getattr(error, 'returncode', 1)
    reporter.finish()
    return 0


if __name__ == '__main__':
    def cancelled(signum, frame):
        raise CommandFailure('Workflow interrupted', 128 + signum)
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    sys.exit(main())
