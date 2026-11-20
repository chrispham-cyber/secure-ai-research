"""Agentic tool use: the model may request functions; the application decides.

Implemented: the agent toolset. The model may request a function, but every authority
check — role and argument validation — is enforced in the application, outside the LLM.
"""
