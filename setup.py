import os
from setuptools import setup

BASEDIR = os.path.abspath(os.path.dirname(__file__))

with open(f"{BASEDIR}/README.md", "r") as fh:
    long_desc = fh.read()


def get_version():
    """ Find the version of the package"""
    version = None
    version_file = os.path.join(BASEDIR, 'hivemind_bus_client', 'version.py')
    major, minor, build, alpha = (None, None, None, None)
    with open(version_file) as f:
        for line in f:
            if 'VERSION_MAJOR' in line:
                major = line.split('=')[1].strip()
            elif 'VERSION_MINOR' in line:
                minor = line.split('=')[1].strip()
            elif 'VERSION_BUILD' in line:
                build = line.split('=')[1].strip()
            elif 'VERSION_ALPHA' in line:
                alpha = line.split('=')[1].strip()

            if ((major and minor and build and alpha) or
                    '# END_VERSION_BLOCK' in line):
                break
    version = f"{major}.{minor}.{build}"
    if int(alpha):
        version += f"a{alpha}"
    return version


def required(requirements_file):
    """ Read requirements file and remove comments and empty lines. """
    base_dir = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(base_dir, requirements_file), 'r') as f:
        requirements = f.read().splitlines()
        return [pkg for pkg in requirements
                if pkg.strip() and not pkg.startswith("#")]


setup(
    name='hivemind_bus_client',
    version=get_version(),
    packages=['hivemind_bus_client', 'hivemind_bus_client.encodings'],
    package_data={
      '*': ['*.txt', '*.md']
    },
    include_package_data=True,
    install_requires=required('requirements.txt'),
    url='https://github.com/JarbasHiveMind/hivemind_websocket_client',
    license='Apache-2.0',
    author='JarbasAi',
    author_email='jarbasai@mailfence.com',
    description='Hivemind Websocket Client',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    entry_points={
        'console_scripts': [
            'hivemind-client=hivemind_bus_client.scripts:hmclient_cmds',
            'hivemind-encoding-bench=hivemind_bus_client.encodings.benchmark:main'
        ]
    }
)
