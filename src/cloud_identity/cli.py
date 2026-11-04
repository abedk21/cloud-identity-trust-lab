"""Run offline synthetic trust policy examples; no credentials are accepted."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
from .policy import authorize, lint_policy


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Offline mock identity policy evaluator (NOT authentication)')
    parser.add_argument('command', choices=['lint', 'evaluate', 'scenarios'])
    parser.add_argument('--policy', type=Path, default=Path(__file__).resolve().parents[2] / 'fixtures' / 'policy.json')
    parser.add_argument('--case', type=Path, default=Path(__file__).resolve().parents[2] / 'fixtures' / 'sample_case.json')
    args = parser.parse_args(argv)
    policy = json.loads(args.policy.read_text())
    if args.command == 'lint':
        issues = lint_policy(policy)
        print(json.dumps({'valid': not issues, 'issues': issues}, indent=2))
        return int(bool(issues))
    case = json.loads(args.case.read_text())
    if args.command == 'scenarios':
        scenario_file = args.case.parent / 'scenarios.json'
        scenarios = json.loads(scenario_file.read_text())['scenarios']
        results=[]
        for s in scenarios:
            run=copy.deepcopy(case)
            run['claims'].update(s.get('claim_overrides', {}))
            run['request'].update(s.get('request_overrides', {}))
            got=authorize(policy, run['claims'], run['request'], now=run['now'])
            passed=got.allowed is s['expected_allowed'] and got.reason == s['expected_reason']
            results.append({'id':s['id'], 'passed':passed,'reason':got.reason})
        print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results),'cases':results},indent=2))
        return int(not all(x['passed'] for x in results))
    decision = authorize(policy, case['claims'], case['request'], now=case['now'])
    print(json.dumps(decision.to_dict(), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
