$ErrorActionPreference = 'SilentlyContinue'

Remove-Item -Recurse -Force .pytest_cache
Get-ChildItem -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -File -Filter '*.pyc' | Remove-Item -Force
