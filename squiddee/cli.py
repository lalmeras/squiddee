# -*- coding: utf-8 -*-

import click

import humanfriendly

import jinja2

import plumbum

import os
import os.path
import sys


@click.command()
@click.option('--directory', '-d',
              help='data root directory (cache, logs, conf, ...)',
              type=click.Path(file_okay=False, resolve_path=True),
              default='./squid_data')
@click.option('--port', '-p', help='proxy listen port', default=3128)
@click.option('--cacert', type=click.File('rb'),
              help='use custom certificate (pem format); if not provided, '
              'new certificate is generated')
@click.option('--cacert-subject',
              help='alternate subject for certificate generation')
@click.option('--cache-size', '-s', help='maximum cache size',
              default='5000 MB')
@click.option('--minimum-object-size', '-m', help='minimum object size',
              default='0')
@click.option('--maximum-object-size', '-m', help='maximum object size',
              default='350 MB')
def main(directory, port, cache_size,
         minimum_object_size, maximum_object_size,
         cacert, cacert_subject):
    if not os.path.exists(directory):
        os.makedirs(directory)
    for path in ('cache', 'logs', 'run', 'certs'):
        abs_path = os.path.join(directory, path)
        if not os.path.exists(abs_path):
            os.makedirs(abs_path)
    cert_path = None
    if cacert is None:
        cert_path = os.path.join(directory, 'certs', 'squiddee.pem')
        subject = None
        if cacert_subject is not None:
            subject = cacert_subject
        else:
            subject = '/C=FR/ST=France/L=Lyon/O=squiddee/OU=squiddee/' \
                      'CN=squiddee.example.org'
        generate_cacert(directory, subject, cert_path, cert_path)
        cacert = cert_path
    conf_file = os.path.join(directory, 'squid.conf')
    ssl_crtd_path = None
    if os.path.exists('/usr/lib64/squid/security_file_certgen'):
        ssl_crtd_path = '/usr/lib64/squid/security_file_certgen'
    else:
        ssl_crtd_path = '/usr/lib64/squid/ssl_crtd'
    generate_configuration(conf_file, directory, port, cache_size,
                           minimum_object_size, maximum_object_size,
                           cacert, ssl_crtd_path)
    squid = plumbum.local['squid']
    if not os.path.exists(os.path.join(directory, 'cache', 'swap.state')):
        squid['-f', conf_file, '-z', '-N'] & plumbum.FG
    if not os.path.exists(os.path.join(directory, 'ssl_db')):
        ssl_crtd = plumbum.local[ssl_crtd_path]
        ssl_crtd['-c', '-s', os.path.join(directory, 'ssl_db')] & plumbum.FG
    squid['-f', conf_file, '-N'] & plumbum.FG
    sys.exit(0)


def generate_configuration(conf_file, directory, port, cache_size,
                           minimum_object_size, maximum_object_size,
                           cacert, ssl_crtd_path):
    loader = jinja2.PackageLoader(__package__)
    env = jinja2.Environment(loader=loader)
    if cache_size is None:
        cache_size = '5 GB'
    cache_size_int = humanfriendly.parse_size(cache_size,
                                              binary=True)
    cache_dir_cfg = None
    folder_size = int(cache_size_int / 1024 ** 2)
    cache_dir_cfg = '{} 16 256'.format(folder_size)
    vars = dict(
        here=directory,
        cacert=cacert,
        ssl_crtd=ssl_crtd_path,
        cache_dir_cfg=cache_dir_cfg,
        minimum_object_size=minimum_object_size,
        maximum_object_size=maximum_object_size,
        port=port
    )
    conf = env.get_template('squid.conf.jinja2').render(**vars)
    with open(conf_file, 'w') as f:
        f.write(conf)


def generate_cacert(directory, cacert_subject,
                    crt_path, key_path):
    openssl = plumbum.local['openssl']
    subject = None
    if cacert_subject is not None:
        subject = cacert_subject
    else:
        subject = '/C=FR/ST=France/L=Lyon/O=squiddee/OU=squiddee/' \
                  'CN=squiddee.example.org'
    gen = openssl['req', '-newkey', 'rsa:2048', '-new', '-nodes', '-x509',
                  '-days', '3650',
                  '-subj', subject,
                  '-out', crt_path,
                  '-keyout', key_path].run()
    if gen[0] == 0:
        return
    else:
        raise Exception('error generating certificate', gen)


if __name__ == "__main__":
    main()
