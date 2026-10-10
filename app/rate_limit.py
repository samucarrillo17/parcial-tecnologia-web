"""Rate limiting (límite de peticiones por IP) con slowapi.

Se define en su propio módulo para que lo puedan importar tanto ``main.py``
como los routers sin crear importaciones circulares.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
