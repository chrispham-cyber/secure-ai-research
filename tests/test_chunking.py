from secure_ai_research.retrieval.chunking import chunk


def test_short_text_is_one_chunk():
    assert chunk("one short sentence.") == ["one short sentence."]


def test_empty_text_is_no_chunks():
    assert chunk("") == []
    assert chunk("   ") == []


def test_long_text_splits_with_overlap():
    words = [f"w{i}" for i in range(50)]
    text = " ".join(words)
    result = chunk(text, size=40, overlap=10)
    assert len(result) > 1
    for c in result:
        assert len(c) <= 40
    # consecutive chunks share at least one word (the overlap)
    for a, b in zip(result, result[1:], strict=False):
        assert set(a.split()) & set(b.split())
    # every word of the input appears in some chunk (nothing dropped)
    seen: list[str] = []
    for c in result:
        seen.extend(c.split())
    assert set(seen) == set(words)


def test_chunking_is_deterministic():
    text = " ".join(f"word{i}" for i in range(30))
    assert chunk(text, size=50, overlap=12) == chunk(text, size=50, overlap=12)
