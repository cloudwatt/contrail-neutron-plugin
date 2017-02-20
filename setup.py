#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#
import os
from setuptools import setup, find_packages


def requirements(filename):
    # no requirements needed for a devstack install
    # FIXME: find a better way to tell we are in devstack
    if '/opt/stack' in os.environ.get('SUDO_COMMAND', ''):
        return []
    with open(filename) as f:
        lines = f.read().splitlines()
    return lines


def get_version():
    """The generated version format is <branchName>+git<abbrevSha>. 
    If the required git commands fail, it falls back to %Y.%m+%d%H%M%S.cw"""
    import subprocess
    from datetime import datetime
    try:
        branch=subprocess.check_output(['git', 'describe', '--tags', '--abbrev=0'])
        sha=subprocess.check_output(['git', 'log', '--abbrev', '--format=format:%h', '-n', '1'])
        return "%s+git%s" % (branch.strip(), sha.strip())
    except subprocess.CalledProcessError:
        return datetime.now().strftime('%Y.%m+%d%H%M%S.cw')


setup(
    name='neutron_plugin_contrail',
    version=get_version(),
    packages=find_packages(),
    package_data={'': ['*.html', '*.css', '*.xml']},
    zip_safe=False,
    long_description="Contrail neutron plugin",

    install_requires=requirements('requirements.txt'),

    test_suite='neutron_plugin_contrail.tests',
    tests_require=requirements('test-requirements.txt'),

    url='https://git.corp.cloudwatt.com/applications/contrail-neutron-plugin',
    author='Jean-Philippe Braun',
    author_email='jean-philippe.braun@cloudwatt.com'
)
