"""Installable Hermes plugin entry point for the zap-proxy repository."""

from .plugin import register

__all__ = ["register"]
