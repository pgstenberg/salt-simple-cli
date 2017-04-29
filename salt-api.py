import sacore as salt
import sys


def main_command(
        conn,
        target,
        action,
        arguments={}):
    salt.thread(target=salt.handle_command, args=(
        conn,
        action,
        target,
        arguments))


def main_hook(
        conn,
        tag,
        success=None,
        failure=None,
        log=None,
        arguments={}):

    if success is None and failure is None and log is None:
        hook_response = conn.send_hook(tag, arguments)
        if hook_response.status_code != 200:
            sys.exit('Hook responded unsuccessfully [{}]:{}'.format(
                hook_response.status_code,
                hook_response.text))
        print("Hook successfully sent!")
        return

    salt.thread(target=salt.handle_hook, args=(
        conn,
        tag,
        success,
        failure,
        log,
        arguments))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description='Simple CLI for Salt-API using async calls and events.')

    # Authentication params
    parser.add_argument(
        '-u',
        '--username',
        help='Username used during authentication.',
        default=None)
    parser.add_argument(
        '-p',
        '--password',
        help='Password used during authentication.',
        default=None)
    parser.add_argument(
        '-a',
        '--auth',
        help='Authentication method used during authentication, default ldap',
        default='ldap')

    # Required URL param
    parser.add_argument(
        'url',
        help='URL to the salt-api.')

    subparsers = parser.add_subparsers()

    # Ordinary command
    parser_cmd = subparsers.add_parser(
        'cmd',
        help='Execute a command using the local_async runner.')
    parser_cmd.set_defaults(which='cmd')
    parser_cmd.add_argument(
        'target',
        help='What minions to target')
    parser_cmd.add_argument(
        'action',
        help='Action to execute on the targeted minions, example "test.ping"')
    parser_cmd.add_argument(
        '-args',
        '--arguments',
        help='Arguments to pass with the command.',
        default={})

    # Hook command
    parser_hook = subparsers.add_parser(
        'hook',
        help='Execute a hook on the salt master.')
    parser_hook.set_defaults(which='hook')
    parser_hook.add_argument(
        'tag',
        help='What minions to target')
    parser_hook.add_argument(
        '-args',
        '--arguments',
        help='Arguments to pass with the hook.',
        default={})
    parser_hook.add_argument(
        '--success',
        help='The successfull tag.',
        default=None)
    parser_hook.add_argument(
        '--fail',
        help='The fail tag.',
        default=None)
    parser_hook.add_argument(
        '--log',
        help='The log tag.',
        default=None)

    try:
        args = vars(parser.parse_args())

        conn = salt.SaltConnection(args['url'])

        if args['username'] is not None and args['password'] is not None:
            session_response = conn.create_session(
                username=args['username'],
                password=args['password'],
                auth=args['auth'])
            if session_response.status_code != 200:
                sys.exit('Unable to authenticate, response [{}]: {}'.format(
                    session_response.status_code,
                    session_response.text))

        # Remove unwanted arguments
        excluded_args = {x: args[x] for x in args if x not in [
            'which',
            'username',
            'password',
            'auth',
            'url']}
        excluded_args['conn'] = conn

        if args['which'] == 'cmd':
            main_command(**excluded_args)
        elif args['which'] == 'hook':
            main_hook(**excluded_args)
    except ValueError as e:
        sys.stderr.write('%s\n' % str(e))
