from setuptools import setup, find_packages

setup(
    name="meda-claw",
    version="3.0.0",
    description="The Independent AI Governance & Security Stack",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Varun Meda",
    author_email="varunmeda95@gmail.com",
    url="https://github.com/VMaroon95/meda-claw",
    packages=find_packages(),
    package_data={"meda_claw": ["policy/*.json"]},
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "colorama>=0.4",
    ],
    extras_require={
        "full": ["requests>=2.28"],
    },
    entry_points={
        "console_scripts": [
            "medaclaw=meda_claw.cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    keywords="ai governance security audit provenance compliance agents",
)
