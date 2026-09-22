import importlib.util
from pathlib import Path

SIM_PATH = Path(__file__).resolve().parents[1] / "simulator" / "encrypt_sim.py"


def _load_sim():
    spec = importlib.util.spec_from_file_location("encrypt_sim", SIM_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sim = _load_sim()


def _sandbox(tmp_path: Path) -> Path:
    target = tmp_path / "sandbox"
    target.mkdir()
    return target


def test_sandbox_guard_rejects_bad_paths(tmp_path):
    assert sim.main(["--target", "/", "--files", "1"]) == 2
    assert sim.main(["--target", str(Path.home()), "--files", "1"]) == 2
    assert sim.main(["--target", r"C:\Windows", "--files", "1"]) == 2
    assert sim.main(["--target", r"C:\Windows\System32", "--files", "1"]) == 2
    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    assert sim.main(["--target", str(git_dir), "--files", "1"]) == 2
    dirty = tmp_path / "documents"
    dirty.mkdir()
    victim = dirty / "invoice.txt"
    victim.write_bytes(b"do-not-touch")
    assert sim.main(["--target", str(dirty), "--files", "1"]) == 2
    assert victim.read_bytes() == b"do-not-touch"
    assert list(dirty.glob("*.locked")) == []
    assert not (dirty / "RANSOM_NOTE.txt").exists()


def test_run_creates_n_locked_files_and_note(tmp_path):
    target = _sandbox(tmp_path)
    n = 8
    rc = sim.main(["--target", str(target), "--files", str(n), "--seed", "1"])
    assert rc == 0
    locked = sorted(p.name for p in target.glob("*.locked"))
    assert locked == [f"file_{i:04d}.txt.locked" for i in range(n)]
    assert (target / "RANSOM_NOTE.txt").is_file()
    assert "100102" in (target / "RANSOM_NOTE.txt").read_text(encoding="utf-8")
    assert not any((target / f"file_{i:04d}.txt").exists() for i in range(n))


def test_rollback_restores_byte_identical_content(tmp_path):
    target = _sandbox(tmp_path)
    n = 6
    assert sim.main(["--target", str(target), "--files", str(n), "--seed", "3"]) == 0
    backup = target / ".sim_backup"
    originals = {
        p.name: p.read_bytes()
        for p in backup.iterdir()
        if p.is_file() and p.name != ".lab_sim"
    }
    assert len(originals) == n
    locked_payload = (target / "file_0000.txt.locked").read_bytes()
    assert locked_payload != originals["file_0000.txt"]
    assert sim.main(["--target", str(target), "--rollback"]) == 0
    for name, data in originals.items():
        restored = target / name
        assert restored.is_file()
        assert restored.read_bytes() == data
    assert list(target.glob("*.locked")) == []
    assert not (target / "RANSOM_NOTE.txt").exists()


def test_running_twice_is_safe(tmp_path):
    target = _sandbox(tmp_path)
    n = 5
    args = ["--target", str(target), "--files", str(n), "--seed", "9"]
    assert sim.main(args) == 0
    first_locked = {
        p.name: p.read_bytes() for p in target.glob("*.locked")
    }
    first_backup = {
        p.name: p.read_bytes()
        for p in (target / ".sim_backup").iterdir()
        if p.is_file() and p.name != ".lab_sim"
    }
    assert sim.main(args) == 0
    second_locked = {
        p.name: p.read_bytes() for p in target.glob("*.locked")
    }
    second_backup = {
        p.name: p.read_bytes()
        for p in (target / ".sim_backup").iterdir()
        if p.is_file() and p.name != ".lab_sim"
    }
    assert len(second_locked) == n
    assert second_locked == first_locked
    assert second_backup == first_backup
    assert (target / "RANSOM_NOTE.txt").is_file()
    assert sim.main(["--target", str(target), "--rollback"]) == 0
    for name, data in first_backup.items():
        assert (target / name).read_bytes() == data
