import requests
import json
import sys
import threading
import os

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

    def create_session(
            self,
            username,
            password,
            auth='ldap',
            headers=DEFAULT_HEADERS):

        auth_data = {
            "username": username,
            "password": password,
            "eauth": auth
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

    def send_hook(self, tag, arguments, headers=DEFAULT_HEADERS):

        response = self.session.post(
            '{}/hook/{}'.format(self.url, tag),
            data=arguments,
            headers=headers)

        return response


def handle_command(connection, function, target, arguments):
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


def handle_hook(
        connection,
        tag,
        success_tag,
        failure_tag,
        log_tag,
        arguments):

    def find_data(key, data):
        if key in data:
            return data[key]
        elif 'data' in data:
            return find_data(key, data['data'])
        else:
            return False

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
        if not line:
            continue

        if 'tag: ' in line:
            tag = line.replace('tag: ', '')
            # Success Event
            if success_tag is not None and tag.find(success_tag) != -1:
                print("Successfull tag was received!")
                return
            # Failure Event
            elif failure_tag is not None and tag.find(failure_tag) != -1:
                sys.exit('Failure tag was received.')
            elif log_tag is not None and tag.find(log_tag) != -1:
                show_next = True
            else:
                show_next = False

        if 'data: ' in line and show_next:
            try:
                event_data = json.loads(line.replace('data: ', ''))
                if (find_data('message', event_data)
                        and find_data('_stamp', event_data)):
                    print("{} - {}".format(
                        find_data('_stamp', event_data),
                        find_data('message', event_data)))
                else:
                    print(json.dumps(event_data))
            except ValueError:
                print("Unable to show log event {}".format(line))


def thread(target, args):
    try:
        t = threading.Thread(target=target, args=args)
        t.start()

        t.join(timeout=60)

        if not t.isAlive():
            return

        print("Timeout was reached, force exit application!")
        os._exit(1)

    except SaltException as e:
        sys.exit(e)
