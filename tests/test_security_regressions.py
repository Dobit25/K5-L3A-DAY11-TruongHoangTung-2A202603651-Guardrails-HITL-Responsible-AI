import asyncio
import base64
from types import SimpleNamespace

import pytest

from assignment.pipeline import is_egress_allowed
from assignment.audit_log import AuditLogPlugin
from guardrails.output_guardrails import content_filter
from core.openai_runtime import OpenAIAgent, OpenAIRunner


def test_protected_host_and_encoded_password_are_redacted():
    for text in ('db.vinbank.internal:5432', base64.b64encode(b'admin123').decode()):
        result = content_filter(text)
        assert not result['safe']
        assert text not in result['redacted']
        assert not is_egress_allowed('https://api.vinbank.example/collect', text)


def test_egress_rejects_unknown_subdomain_and_credentials():
    assert not is_egress_allowed('https://attacker.vinbank.example/collect', 'banking')
    assert not is_egress_allowed('https://user@api.vinbank.example/collect', 'banking')


def test_audit_redacts_before_retaining_input():
    audit = AuditLogPlugin()
    audit.record_input(user_id='u', text='admin123 test@example.com', request_id='r')
    audit.record_output(user_id='u', text='db.vinbank.internal:5432', request_id='r')
    assert all('admin123' not in row['text'] and 'test@example.com' not in row['text']
               and 'db.vinbank.internal' not in row['text'] for row in audit.logs)
    assert [row['request_id'] for row in audit.logs] == ['r', 'r']


def test_api_failure_cannot_become_successful_banking_answer(monkeypatch):
    def fail(**kwargs):
        raise ValueError('private provider failure')
    monkeypatch.setattr(OpenAIRunner, '_client', lambda self: SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fail))))
    with pytest.raises(RuntimeError, match='LLM request failed'):
        asyncio.run(OpenAIRunner('test', 'test').chat(OpenAIAgent('test', 'test'), 'balance'))
