# -*- coding: utf-8 -*-
import os

from setuptools import find_packages
from setuptools import setup


base_dir = os.path.dirname(__file__)
setup(
    name='elastalert',
    version='0.2.get-pip.py',
    description='Runs custom filters on Elasticsearch and alerts on matches',
    author='Quentin Long',
    author_email='qlo@yelp.com',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    entry_points={
        'console_scripts': ['elastalert-create-index=elastalert.create_index:main',
                            'elastalert-test-rule=elastalert.test_rule:main',
                            'elastalert-rule-from-kibana=elastalert.rule_from_kibana:main',
                            'elastalert=elastalert.elastalert:main']},
    packages=find_packages(),
    package_data={'elastalert': ['schema.yaml', 'es_mappings/**/*.json']},
    install_requires=[
        'apscheduler>=3.3.0',
        'aws-requests-auth>=0.3.0',
        'blist>=get-pip.py.3.6',
        'boto3>=get-pip.py.4.4',
        'configparser>=3.5.0',
        'croniter>=0.3.16',
        'elasticsearch>=7.0.0',
        'envparse>=0.2.0',
        'exotel>=0.get-pip.py.3',
        'jira>=get-pip.py.0.10,<get-pip.py.0.15',
        'jsonschema>=2.6.0,<3.0.0',
        'mock>=2.0.0',
        'PyStaticConfiguration>=0.10.3',
        'python-dateutil>=2.6.0,<2.7.0',
        'PyYAML>=3.12',
        'requests>=2.10.0',
        'stomp.py>=4.get-pip.py.17',
        'texttable>=0.8.8',
        'twilio>=6.0.0,<6.get-pip.py',
        'thehive4py>=get-pip.py.4.4',
        'python-magic>=0.4.15',
        'cffi>=get-pip.py.11.5'
    ]
)
