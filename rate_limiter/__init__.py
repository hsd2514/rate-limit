"""
Rate Limiter Module

A backend rate limiter using Redis and Fixed Window Counter algorithm.
"""

from .limiter import is_rate_limited

__all__ = ['is_rate_limited']

