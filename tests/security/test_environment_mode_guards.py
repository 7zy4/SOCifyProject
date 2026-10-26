import pytest


@pytest.mark.parametrize("value", ["production", "PRODUCTION", " Production "])
def test_development_environment_never_prepares_production_keys(monkeypatch, tmp_path, value):
    from scripts.environment import load_environment

    monkeypatch.setenv("SOCIFY_ENV", value)
    with pytest.raises(RuntimeError, match="Production requires"):
        load_environment(tmp_path)
    assert not (tmp_path / "instance").exists()


@pytest.mark.parametrize("value", ["production", "PRODUCTION", " Production "])
def test_development_server_never_starts_in_a_normalized_production_mode(monkeypatch, value):
    import run

    monkeypatch.setenv("SOCIFY_ENV", value)
    monkeypatch.setattr(run, "create_app", lambda: pytest.fail("Production must not start the development application"))
    with pytest.raises(RuntimeError, match="Use Gunicorn"):
        run.main()
