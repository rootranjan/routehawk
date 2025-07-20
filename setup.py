#!/usr/bin/env python3
"""
Setup script for RouteHawk Attack Surface Discovery Tool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="routehawk-attack-surface-tool",
    version="1.0.0",
    author="Ranjan Kumar", 
    author_email="rootranjan+routehawk@gmail.com",
    description="AI-powered API attack surface discovery tool for modern web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rootranjan/routehawk",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "routehawk=routehawk:main",
            "routehawk-web=web.app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yml", "*.yaml", "*.html", "*.css", "*.js"],
        "config": ["*.yml", "*.yaml"],
        "web": ["templates/*.html", "static/css/*.css", "static/js/*.js"],
    },
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
        ],
    },
) 