"""Setup script for Brok"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="brok",
    version="0.1.0",
    author="Brok Team",
    description="Autonomous Penetration Testing Agent powered by AI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/brok",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "jim=cli.main:app",
            "brok=cli.main:app",
        ],
    },
)

