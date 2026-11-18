def test_package_imports_and_has_version():
    import secure_ai_research

    assert secure_ai_research.__version__ == "0.1.0"
