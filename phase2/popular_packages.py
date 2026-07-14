"""
popular_packages.py
-------------------
The top most-downloaded PyPI packages.
Your typosquatting detector will compare every scanned
package name against this list.

In a real production tool, you'd fetch this list live from
https://hugovk.github.io/top-pypi-packages/
For now we hardcode the top 50 — enough to catch real attacks.
"""

TOP_PYPI_PACKAGES = [
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "scipy",
    "matplotlib",
    "tensorflow",
    "torch",
    "scikit-learn",
    "boto3",
    "sqlalchemy",
    "fastapi",
    "pydantic",
    "celery",
    "redis",
    "pillow",
    "pytest",
    "black",
    "mypy",
    "click",
    "httpx",
    "aiohttp",
    "uvicorn",
    "gunicorn",
    "cryptography",
    "paramiko",
    "fabric",
    "ansible",
    "docker",
    "kubernetes",
    "airflow",
    "arrow",
    "attrs",
    "charset-normalizer",
    "certifi",
    "urllib3",
    "idna",
    "six",
    "packaging",
    "setuptools",
    "wheel",
    "pip",
    "virtualenv",
    "tqdm",
    "rich",
    "typer",
    "loguru",
    "python-dotenv",
    "pyyaml",
]