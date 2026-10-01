import pathlib
import subprocess
import sys

SRC = pathlib.Path("engine/killchain/pathfinder.py")
ORIG = SRC.read_text(encoding="utf-8")

GUARD = (
    "            if cost > visited.get(current, float(\"inf\")):\n"
    "                continue\n"
)
RELAX = "if new_cost < visited.get(neighbor, float(\"inf\")):"
RELAX_BAD = "if new_cost > visited.get(neighbor, float(\"inf\")):"
COST = "                new_cost = cost + step_cost"
COST_BAD = "                new_cost = cost + step_cost + 0.5"
TIE = "                    heapq.heappush(pq, (new_cost, neighbor, path + [neighbor]))"
TIE_BAD = "                    heapq.heappush(pq, (new_cost + 1e-9, neighbor, path + [neighbor]))"

MUTANTS = [
    ("remove the stale-entry guard", GUARD, ""),
    ("relax with > instead of <", RELAX, RELAX_BAD),
    ("perturb every step cost by +0.5", COST, COST_BAD),
    ("perturb the queue key by 1e-9", TIE, TIE_BAD),
]


def run_tests() -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_pathfinder.py", "-q"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    tail = [l for l in proc.stdout.splitlines() if "passed" in l or "failed" in l]
    return proc.returncode, (tail[-1] if tail else "?")


try:
    for name, find, replace in MUTANTS:
        if find not in ORIG:
            print(f"SKIP  {name}: anchor not found")
            continue
        SRC.write_text(ORIG.replace(find, replace, 1), encoding="utf-8")
        code, summary = run_tests()
        verdict = "CAUGHT" if code != 0 else "SURVIVED  <-- test is blind here"
        print(f"{verdict:9} {name}: {summary}")
finally:
    SRC.write_text(ORIG, encoding="utf-8")
    code, summary = run_tests()
    print(f"\nrestored: {summary}")
