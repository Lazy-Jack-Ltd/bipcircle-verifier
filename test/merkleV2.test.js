// POR-MERKLE-V1-MALLEABLE-02 (whitehat sweep 3): the verifier must compute the
// RFC-6962 domain-separated v2 root byte-identically to the BIPCircle producer
// (sealMerkle.js computeMerkleRootV2), and dispatch on witness.protocolVersion
// so v1 witnesses still verify. The SHARED_VECTOR roots below are asserted in
// BOTH repos — any drift between producer and verifier fails the build.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeMerkleRoot, computeMerkleRootV2, computeMerkleRootForVersion } from '../src/merkle.js';

// Cross-repo shared test vector — 3 leaves, identical to the producer's pin.
const SHARED_LEAVES = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];
const SHARED_V1_ROOT = 'e046522f24b39f1a9a2cf96bebcd386df477f282d7ac9b61d0ca59d8fe8f81b6';
const SHARED_V2_ROOT = '9bee4401962e94b921336a7910a5a9718836ffcbc545dde0a3f34d858beb5752';

test('v2 root matches the cross-repo shared vector (byte-identical to the producer)', () => {
  assert.equal(computeMerkleRootV2(SHARED_LEAVES), SHARED_V2_ROOT);
});

test('v1 root matches the cross-repo shared vector', () => {
  assert.equal(computeMerkleRoot(SHARED_LEAVES), SHARED_V1_ROOT);
});

test('v2 differs from v1 for the same leaves (domain separation is in effect)', () => {
  assert.notEqual(computeMerkleRootV2(SHARED_LEAVES), computeMerkleRoot(SHARED_LEAVES));
});

test('computeMerkleRootForVersion dispatches on protocolVersion', () => {
  assert.equal(computeMerkleRootForVersion(SHARED_LEAVES, 'v2'), SHARED_V2_ROOT);
  assert.equal(computeMerkleRootForVersion(SHARED_LEAVES, 'v1'), SHARED_V1_ROOT);
  // Absent / unknown version falls back to v1 (already-published witnesses).
  assert.equal(computeMerkleRootForVersion(SHARED_LEAVES, undefined), SHARED_V1_ROOT);
  assert.equal(computeMerkleRootForVersion(SHARED_LEAVES, 'v9'), SHARED_V1_ROOT);
});

test('odd-leaf set is not malleable under v2 (promotion, not duplication)', () => {
  // v1 (CVE-2012-2459): a 3-leaf tree duplicates the last leaf. v2 promotes it
  // unchanged. The two roots must differ, proving v2 does not duplicate.
  const odd = ['aa'.repeat(32), 'bb'.repeat(32), 'cc'.repeat(32)];
  assert.notEqual(computeMerkleRootV2(odd), computeMerkleRoot(odd));
});

test('empty input → null for both versions', () => {
  assert.equal(computeMerkleRootV2([]), null);
  assert.equal(computeMerkleRootForVersion([], 'v2'), null);
});
