import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core import searcher


def test_dedup_key_prefers_job_id():
    a = searcher._dedup_key("Acme Inc.", "JR-123", "Senior PM")
    b = searcher._dedup_key("acme inc", "jr123", "Completely Different Title")
    assert a == b  # same company + job id should collide regardless of formatting


def test_dedup_key_falls_back_to_title():
    a = searcher._dedup_key("Acme", "", "Senior Product Manager")
    b = searcher._dedup_key("Acme", "", "senior product manager")
    assert a == b


def test_extract_json_array_from_fenced_block():
    text = 'Here is what I found:\n```json\n[{"a": 1}]\n```\n'
    assert searcher._extract_json_array(text) == [{"a": 1}]


def test_extract_json_array_without_fence_falls_back():
    assert searcher._extract_json_array("[]") == []


def test_extract_json_array_rejects_non_array():
    with pytest.raises(searcher.SearchError):
        searcher._extract_json_array('```json\n{"not": "a list"}\n```')


def test_extract_json_array_rejects_garbage():
    with pytest.raises(searcher.SearchError):
        searcher._extract_json_array("not json at all")


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeTextBlock(text)]


def test_search_jobs_dedupes_against_already_seen(monkeypatch):
    monkeypatch.setattr(searcher, "_client", lambda: _FakeClientReturning(
        '```json\n[{"company": "Acme", "role": "Senior PM", "job_id": "JR-1", '
        '"tier": "strong", "location": "Remote", "posting_date": "2026-01-01", '
        '"link": "http://x", "description": "d"}]\n```'
    ))
    results = searcher.search_jobs(
        resume_text="resume",
        target_roles=None,
        companies=[{"name": "Acme"}],
        already_seen=[{"company": "Acme", "role": "Senior PM", "job_id": "JR-1"}],
    )
    assert results == []  # already seen, should be filtered out


class _FakeMessages:
    def __init__(self, text):
        self._text = text

    def create(self, **kwargs):
        return _FakeResponse(self._text)


class _FakeClientReturning:
    def __init__(self, text):
        self.messages = _FakeMessages(text)
