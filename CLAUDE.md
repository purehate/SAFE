# SAFE - Simulated Adversary File Events

## Project
- **Purpose**: Non-destructive security testing framework for purple teams and detection engineering
- **Language**: Python 3.7+ (standard library only, zero external dependencies)
- **Entry points**: `python3 SAFE.py` or `python3 -m safe`

## Module Structure
```
safe/
├── __init__.py          # Package docstring
├── __main__.py          # python -m safe entry point
├── constants.py         # EXTENSIONS list, THREAT_PROFILES dict
├── ioc_simulator.py     # IOCSimulator class, MITRE ATT&CK data
├── persistence.py       # PersistenceSimulator (Windows/macOS/Linux)
├── process.py           # ProcessSimulator (EDR/XDR patterns)
├── simulator.py         # Main Simulator class, menu loop, main()
├── system_info.py       # get_system_info(), get_desktop()
└── utils.py             # random_filename(), fake_ciphertext(), make_note_text()
```

## Coding Guidelines

1. **NEVER** bare `except:` — always specify exception types
2. **NEVER** `eval()`/`exec()` with user input
3. **ALWAYS** type hints on function signatures
4. **ALWAYS** docstrings on classes and public methods
5. **NEVER** files > 500 lines — split into modules
6. Use `logging.getLogger(__name__)`, never `print()`
7. Logging is configured with `%(message)s` format in `main()` for clean CLI output
8. Use `Path.write_text()` / `Path.read_text()` over manual `open()`/`close()` where practical
9. Use `shutil.rmtree()` for directory cleanup, never manual `os.walk` removal
10. Keep `SAFE.py` as a thin wrapper — all logic lives in the `safe/` package

## Architecture Notes

- **IOCSimulator** requires `system_info` dict (from `get_system_info()`) in its constructor
- **PersistenceSimulator** and **ProcessSimulator** are OS-aware — they check `system_info["type"]` and only generate artifacts for the current platform
- All simulators take `base_dir` as first arg — this gets set to the simulation output directory at runtime
- Threat profiles and MITRE data are static dicts, not classes — keep them as data
- Menu uses `sys.stdout.write("\033c")` for screen clearing (terminal control, not logging)

## Git
- **Branch**: main
- **Repo**: `git@github.com:purehate/SAFE.git`
- **Identity**: `purehate <twentycab@gmail.com>`
- Commit format: `<type>(<scope>): <description>` — types: feat, fix, refactor, chore, docs, perf, test
