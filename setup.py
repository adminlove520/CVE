from setuptools import setup, find_packages

setup(
    name="cve-monitor",
    version="0.1",
    packages=find_packages(include=['backend', 'backend.*']),
    install_requires=[
        "requests==2.31.0",
        "python-dotenv==1.0.0",
        "beautifulsoup4==4.12.2",
        "lxml==4.9.3"
    ]
) 