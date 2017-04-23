import requests
import json
import sys
import threading

from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter


def prettyPrint(data):
    print(highlight(
        json.dumps(data, indent=2),
        JsonLexer(),
        TerminalFormatter()))


class SaltException(Exception):
    pass


class SaltConnection(object):

    DEFAULT_HEADERS = {
        "Content-type": "application/json",
        "Accept": "application/json"
    }

    def __init__(self, url):
        self.url = url
        self.session = requests.Session()

    def create_session(self, username, password, headers=DEFAULT_HEADERS):

        auth_data = {
            "username": username,
            "password": password,
            "eauth": "ldap"
        }

        response = self.session.post(
            '{}/login'.format(self.url),
            data=json.dumps(auth_data),
            headers=headers)

        return response

    def event_stream(self, timeout=20, headers=DEFAULT_HEADERS):

        response = self.session.get(
            '{}/events'.format(self.url),
            stream=True,
            timeout=timeout)

        if response.encoding is None:
            response.encoding = 'utf-8'

        return response

    def send_command(
            self,
            function,
            target,
            arguments={},
            headers=DEFAULT_HEADERS):

        cmd_data = {
            "client": "local_async",
            "tgt": target,
            "fun": function,
            "kwarg": json.dumps(arguments)
        }

        response = self.session.post(
            '{}'.format(self.url),
            data=json.dumps(cmd_data),
            headers=headers)

        return response

    def send_hook(self, tag, arguments={}, headers=DEFAULT_HEADERS):

        response = self.session.post(
            '{}/hook/{}'.format(self.url, tag),
            data=json.dumps(arguments),
            headers=headers)

        return response


def handle_command(connection, function, target, arguments={}):
    stream = connection.event_stream()
    command_response = connection.send_command(
        function=function,
        target=target,
        arguments=arguments)

    if command_response.status_code != 200:
        raise SaltException('Command responded unexpectedly [{}]: {}'.format(
                command_response.status_code,
                command_response.text))

    if stream.status_code != 200:
        raise SaltException('Stream responded unexpectedly [{}]: {}'.format(
                stream.status_code,
                stream.text))

    expected_minions = command_response.json()['return'][0]['minions']
    jid = command_response.json()['return'][0]['jid']

    print('Wating for result from: {}'.format(expected_minions))

    success = True

    for line in stream.iter_lines(decode_unicode=True, chunk_size=2):
        if line and 'data: ' in line:
            event_data = json.loads(line.replace('data: ', ''))['data']
            if 'jid' in event_data and 'id' in event_data:
                if event_data['id'] in expected_minions \
                        and event_data['jid'] == jid:
                    expected_minions.remove(event_data['id'])
                    prettyPrint({event_data['id']: event_data['return']})
                    if not event_data['success']:
                        success = False

        if not expected_minions:
            return

    if not success:
        sys.exit('Some of the minions run unsuccessfully.')


def handle_hook(connection, tag, success_tag, failure_tag, arguments={}):
    stream = connection.event_stream()
    hook_response = connection.send_hook(tag, arguments)

    if hook_response.status_code != 200:
        raise SaltException('Command responded unexpectedly [{}]: {}'.format(
                hook_response.status_code,
                hook_response.text))

    if stream.status_code != 200:
        raise SaltException('Stream responded unexpectedly [{}]: {}'.format(
                stream.status_code,
                stream.text))

    for line in stream.iter_lines(decode_unicode=True, chunk_size=2):
        if line and 'tag: ' in line:
            tag_received = line.replace('tag: ', '')
            if tag_received == success_tag:
                print("Successfull tag was received!")
                return
            elif tag_received == failure_tag:
                sys.exit('Failure tag was received.')


def thread(target, args):
    try:
        t = threading.Thread(target=target, args=args)
        t.start()

        t.join(timeout=60)

        if not t.isAlive():
            return

        raise SaltException('Timeout.')

    except SaltException as e:
        sys.exit(e)


def main_command(conn, function, target, arguments={}):
    thread(target=handle_command, args=(
        conn,
        function,
        target,
        arguments))


def main_hook(conn, tag, arguments={}, success_tag=None, failure_tag=None):

    if success_tag is None and failure_tag is None:
        hook_response = conn.send_hook(tag, arguments)
        if hook_response.status_code != 200:
            sys.exit('Hook responded unsuccessfully [{}]:{}'.format(
                hook_response.status_code,
                hook_response.text))
        print("Hook successfully sent!")
        return

    thread(target=handle_hook, args=(
        conn,
        tag,
        success_tag,
        failure_tag,
        arguments))


def main():
    if len(sys.argv) < 5:
        print("url username password cmd function target [arguments]")
        print(
            "url username password hook tag [success_tag] " +
            "[failure_tag] [arguments]")

    url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    type = sys.argv[4]

    if type != 'cmd' and type != 'hook':
        sys.exit(
            'Type expect to be either cmd or hook but was {}'.format(type))

    print('Trying to authorize user {} against url {}.'.format(username, url))

    conn = SaltConnection(url)
    session_response = conn.create_session(
        username=username,
        password=password)
    if session_response.status_code != 200:
        sys.exit('Unable to authenticate, response [{}]: {}'.format(
            session_response.status_code,
            session_response.text))

    print("Authorization successfull!")

    if type == 'cmd':
        if len(sys.argv) == 7:
            main_command(conn, sys.argv[5], sys.argv[6])
        elif len(sys.argv) == 8:
            main_command(conn, sys.argv[5], sys.argv[6], sys.argv[7])

    if type == 'hook':
        if len(sys.argv) == 6:
            main_hook(conn, sys.argv[5])
        elif len(sys.argv) == 7:
            main_hook(conn, sys.argv[5], sys.argv[6])
        elif len(sys.argv) == 8:
            main_hook(conn, sys.argv[5], sys.argv[6], sys.argv[7])


if __name__ == "__main__":
    main()
