'use strict';

const { test, expect } = require('@playwright/test');

async function simulate(page, scenario) {
  await page.getByTestId(`simulate-${scenario}`).click();
  await expect(page.getByTestId('report')).toBeVisible();
}

test.describe('CI/CD Security Audit report', () => {
  test.beforeEach(async ({ page }) => {
    // Any CSP violation or script error fails the test: the UI has to work
    // under the strict policy, not around it.
    page.on('console', (msg) => {
      if (msg.type() === 'error') throw new Error(`console error: ${msg.text()}`);
    });
    page.on('pageerror', (err) => {
      throw err;
    });
    await page.goto('/');
  });

  test('is served with a strict CSP and no inline script', async ({ page, request }) => {
    const res = await request.get('/');
    const csp = res.headers()['content-security-policy'];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe');
    expect(res.headers()['x-frame-options']).toBe('SAMEORIGIN');
    expect(await page.locator('script:not([src])').count()).toBe(0);
    await expect(page.getByTestId('policy-digest')).toContainText('policy');
  });

  test('payments: shows the verified badge, the repair loop and the diff', async ({ page }) => {
    await simulate(page, 'payments');

    const badge = page.getByTestId('opa-badge');
    await expect(badge).toHaveAttribute('data-verdict', 'VERIFIED');
    await expect(badge).toContainText('OPA verified');
    await expect(badge).toContainText('8 violations before the patch, 0 after');
    await expect(page.getByTestId('violations-after')).toHaveText('0');

    // Attempt 1 fails the policy gate, attempt 2 is accepted.
    await expect(page.getByTestId('attempt-1')).toHaveAttribute('data-accepted', 'false');
    await expect(page.getByTestId('attempt-1')).toContainText('TF009 aws_db_instance.ledger');
    await expect(page.getByTestId('attempt-2')).toHaveAttribute('data-accepted', 'true');

    await expect(page.getByTestId('findings').locator('tbody tr')).toHaveCount(8);
    await expect(page.getByTestId('findings')).toContainText('After policy feedback');

    const diff = page.getByTestId('diff');
    await expect(page.getByTestId('diff-status')).toHaveText('Accepted patch');
    await expect(diff.locator('[data-diff-sign="-"]', { hasText: 'publicly_accessible    = true' })).toBeVisible();
    await expect(diff.locator('[data-diff-sign="+"]', { hasText: 'publicly_accessible    = false' })).toBeVisible();
    await expect(diff.locator('[data-diff-sign="+"]', { hasText: 'aws_s3_bucket_public_access_block' })).toBeVisible();
    await expect(page.getByTestId('fix-branch')).toContainText('iac-guardian/pr-42-');
  });

  test('injection: the rejected backdoor is visible, the shipped patch is clean', async ({ page }) => {
    await simulate(page, 'injection');
    await expect(page.getByTestId('opa-badge')).toHaveAttribute('data-verdict', 'VERIFIED');

    // The accepted attempt is shown by default and contains no backdoor.
    await expect(page.getByTestId('diff-status')).toHaveText('Accepted patch');
    await expect(page.getByTestId('diff')).not.toContainText('local-exec');

    // The first attempt is kept as evidence of what was blocked.
    await page.getByTestId('attempt-1').click();
    await expect(page.getByTestId('diff-status')).toHaveText('Rejected proposal, not applied');
    await expect(page.getByTestId('diff')).toContainText('local-exec');
    await expect(page.getByTestId('attempt-1')).toContainText('resource-added');
  });

  test('iam: shows a rejected badge when no patch can be verified', async ({ page }) => {
    await simulate(page, 'iam');
    const badge = page.getByTestId('opa-badge');
    await expect(badge).toHaveAttribute('data-verdict', 'REJECTED');
    await expect(badge).toContainText('OPA rejected');
    await expect(page.getByTestId('violations-after')).toHaveText('1');
    await expect(page.getByTestId('attempts').locator('> li')).toHaveCount(3);
    await expect(page.getByTestId('fix-branch')).toHaveCount(0);
  });

  test('clean: reports a compliant pull request without a diff', async ({ page }) => {
    await simulate(page, 'clean');
    await expect(page.getByTestId('opa-badge')).toContainText('OPA passed');
    await expect(page.getByTestId('diff')).toHaveCount(0);
  });

  test('attestation can be verified from the report', async ({ page }) => {
    await simulate(page, 'kubernetes');
    await page.getByTestId('verify-attestation').click();
    await expect(page.getByTestId('attestation-result')).toHaveText('Signature valid');
    await expect(page.getByTestId('attestation')).toContainText('Hash chain intact');
  });

  test('audit list keeps earlier reports selectable', async ({ page }) => {
    await simulate(page, 'clean');
    await simulate(page, 'iam');
    const items = page.getByTestId('audit-item');
    expect(await items.count()).toBeGreaterThanOrEqual(2);
    await items.filter({ hasText: 'network-infra' }).first().click();
    await expect(page.getByTestId('opa-badge')).toHaveAttribute('data-verdict', 'CLEAN');
  });

  test('cross-site requests cannot trigger a simulation', async ({ request }) => {
    const res = await request.post('/api/demo/payments');
    expect(res.status()).toBe(403);
  });
});
