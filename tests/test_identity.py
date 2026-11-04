import copy
import json
import unittest
from pathlib import Path
from cloud_identity.policy import authorize, lint_policy

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'fixtures/policy.json').read_text())
CASE = json.loads((ROOT / 'fixtures/sample_case.json').read_text())


class IdentityPolicyTests(unittest.TestCase):
    def test_lint_valid(self): self.assertEqual(lint_policy(POLICY), [])
    def test_valid_read(self): self.assertTrue(self.evaluate().allowed)
    def test_no_credential_leak(self): self.assertNotIn('sub', str(self.evaluate().to_dict()))

    def evaluate(self, claim=None, value=None, req=None, policy=None):
        case = copy.deepcopy(CASE)
        if claim: case['claims'][claim] = value
        if req: case['request'].update(req)
        return authorize(policy or POLICY, case['claims'], case['request'], now=case['now'])

    def test_wrong_issuer(self): self.assertEqual(self.evaluate('iss','https://evil.invalid').reason,'ISSUER_MISMATCH')
    def test_wrong_audience(self): self.assertEqual(self.evaluate('aud','a-bad-suffix').reason,'AUDIENCE_MISMATCH')
    def test_audience_list_exact(self): self.assertTrue(self.evaluate('aud',[POLICY['audience'],'other']).allowed)
    def test_audience_substring_attack(self): self.assertFalse(self.evaluate('aud',POLICY['audience']+'-suffix').allowed)
    def test_expired(self): self.assertEqual(self.evaluate('exp',CASE['now']).reason,'EXPIRED')
    def test_future_iat(self): self.assertEqual(self.evaluate('iat',CASE['now']+61).reason,'NOT_YET_VALID')
    def test_future_nbf(self): self.assertEqual(self.evaluate('nbf',CASE['now']+61).reason,'NOT_YET_VALID')
    def test_old_iat(self): self.assertEqual(self.evaluate('iat',CASE['now']-1801).reason,'INVALID_TOKEN_AGE')
    def test_boolean_timestamp_not_int(self): self.assertEqual(self.evaluate('exp',True).reason,'INVALID_TIMESTAMP')
    def test_wrong_org_id(self): self.assertEqual(self.evaluate('repository_owner_id','org-other').reason,'ORG_NOT_ALLOWED')
    def test_repo_name_collision(self): self.assertEqual(self.evaluate('repository','sample-org/agent-runtime-fork').reason,'REPOSITORY_NOT_ALLOWED')
    def test_branch_prefix_attack(self): self.assertEqual(self.evaluate('ref','refs/heads/main-hack').reason,'REF_NOT_ALLOWED')
    def test_spoofed_subject(self): self.assertEqual(self.evaluate('sub','repo:other:ref:refs/heads/main').reason,'SUBJECT_BINDING_MISMATCH')
    def test_denied_write(self): self.assertEqual(self.evaluate(req={'action':'delete'}).reason,'NO_MATCHING_BINDING')
    def test_resource_prefix_attack(self): self.assertFalse(self.evaluate(req={'resource':'projects/demo/artifacts-secret/key'}).allowed)
    def test_resource_traversal(self): self.assertEqual(self.evaluate(req={'resource':'projects/demo/artifacts/../secrets'}).reason,'INVALID_RESOURCE_OR_ACTION')
    def test_encoded_resource_traversal(self): self.assertFalse(self.evaluate(req={'resource':'projects/demo/artifacts/%2e%2e/secrets'}).allowed)
    def test_other_environment(self): self.assertFalse(self.evaluate('environment','production').allowed)
    def test_publish_in_prod(self):
        case=copy.deepcopy(CASE);case['claims']['environment']='production';case['request']={'action':'create','resource':'projects/demo/releases/v3'}
        self.assertEqual(authorize(POLICY,case['claims'],case['request'],now=case['now']).binding,'prod-release-publisher')
    def test_deny_broken_policy(self):
        p=copy.deepcopy(POLICY);p['allowed_org_ids']=['*']
        self.assertEqual(self.evaluate(policy=p).reason,'INVALID_POLICY')
    def test_undefined_role(self):
        p=copy.deepcopy(POLICY);p['bindings'][0]['role']='ghost'
        self.assertIn('undefined_role:0',lint_policy(p))
    def test_duplicate_binding_name(self):
        p=copy.deepcopy(POLICY);p['bindings'][1]['name']=p['bindings'][0]['name']
        self.assertIn('invalid_binding_name:1',lint_policy(p))
    def test_unknown_resource(self): self.assertFalse(self.evaluate(req={'resource':'projects/demo/private/file'}).allowed)
    def test_synthetic_scenarios(self):
        from cloud_identity.cli import main
        from contextlib import redirect_stdout
        import io
        with redirect_stdout(io.StringIO()) as buf:
            status=main(['scenarios'])
        self.assertEqual(status,0)
        self.assertIn('"passed": 9',buf.getvalue())

    def test_star_resource_rule_rejected(self):
        p=copy.deepcopy(POLICY);p['permissions']['artifactReader'][0]['resource']='*'
        self.assertIn('invalid_resource_rule:artifactReader:0',lint_policy(p))
    def test_partial_star_resource_rejected(self):
        p=copy.deepcopy(POLICY);p['permissions']['artifactReader'][0]['resource']='projects/demo/*/private'
        self.assertTrue(lint_policy(p))



if __name__=='__main__':unittest.main()
