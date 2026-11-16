'use strict';

const { RestGitHub } = require('../src/github/client');

// Fake fetch that records requests and answers from a route table.
function fakeFetch(routes) {
  const calls = [];
  const impl = async (url, init) => {
    const key = `${init.method} ${new URL(url).pathname}`;
    calls.push({ key, url, init, body: init.body ? JSON.parse(init.body) : undefined });
    const route = routes[key];
    if (!route) return { ok: false, status: 404, json: async () => ({ message: 'secret detail from upstream' }) };
    return { ok: true, status: 200, json: async () => (typeof route === 'function' ? route(calls.at(-1)) : route) };
  };
  return { impl, calls };
}

const TOKEN = 'test-token-value';

describe('GitHub REST client', () => {
  test('opens a fix PR as one commit on a new branch', async () => {
    const { impl, calls } = fakeFetch({
      'GET /repos/acme/infra/git/commits/abc': { tree: { sha: 'tree0' } },
      'POST /repos/acme/infra/git/trees': { sha: 'tree1' },
      'POST /repos/acme/infra/git/commits': { sha: 'commit1' },
      'POST /repos/acme/infra/git/refs': { ref: 'refs/heads/fix' },
      'POST /repos/acme/infra/pulls': { number: 9, html_url: 'https://github.com/acme/infra/pull/9' },
    });
    const gh = new RestGitHub({ token: TOKEN, fetchImpl: impl });

    const pr = await gh.openFixPullRequest({
      owner: 'acme',
      repo: 'infra',
      headRef: 'feature/x',
      headSha: 'abc',
      branch: 'iac-guardian/pr-1-deadbeef',
      files: [{ path: 'main.tf', content: 'x' }],
      title: 't',
      body: 'b',
    });

    expect(pr).toEqual({ number: 9, url: 'https://github.com/acme/infra/pull/9', branch: 'iac-guardian/pr-1-deadbeef' });
    expect(calls.map((c) => c.key)).toEqual([
      'GET /repos/acme/infra/git/commits/abc',
      'POST /repos/acme/infra/git/trees',
      'POST /repos/acme/infra/git/commits',
      'POST /repos/acme/infra/git/refs',
      'POST /repos/acme/infra/pulls',
    ]);
    expect(calls[1].body).toEqual({ base_tree: 'tree0', tree: [{ path: 'main.tf', mode: '100644', type: 'blob', content: 'x' }] });
    expect(calls[2].body.parents).toEqual(['abc']);
    expect(calls[4].body).toMatchObject({ head: 'iac-guardian/pr-1-deadbeef', base: 'feature/x' });
    for (const c of calls) {
      expect(c.init.headers.authorization).toBe(`Bearer ${TOKEN}`);
      expect(c.init.redirect).toBe('error');
    }
  });

  test('fetches only analysable files from a pull request', async () => {
    const b64 = (s) => Buffer.from(s).toString('base64');
    const { impl, calls } = fakeFetch({
      'GET /repos/acme/infra/pulls/3/files': [
        { filename: 'infra/main.tf', status: 'modified' },
        { filename: 'README.md', status: 'modified' },
        { filename: 'infra/old.tf', status: 'removed' },
        { filename: 'k8s/app.yaml', status: 'added' },
      ],
      'GET /repos/acme/infra/contents/infra/main.tf': { encoding: 'base64', size: 10, content: b64('resource {}') },
      'GET /repos/acme/infra/contents/k8s/app.yaml': { encoding: 'base64', size: 10, content: b64('kind: Pod') },
    });
    const gh = new RestGitHub({ token: TOKEN, fetchImpl: impl });

    const files = await gh.getPullRequestFiles({ owner: 'acme', repo: 'infra', number: 3, sha: 'a'.repeat(40) });
    expect(files).toEqual([
      { path: 'infra/main.tf', content: 'resource {}' },
      { path: 'k8s/app.yaml', content: 'kind: Pod' },
    ]);
    expect(calls).toHaveLength(3);
    expect(calls[1].url).toContain(`ref=${'a'.repeat(40)}`);
  });

  test('errors never include the token or the upstream response body', async () => {
    const { impl } = fakeFetch({});
    const gh = new RestGitHub({ token: TOKEN, fetchImpl: impl });
    const err = await gh.setStatus({ owner: 'acme', repo: 'infra', sha: 'abc', state: 'success', description: 'ok' }).catch((e) => e);
    expect(err.message).toBe('GitHub POST /repos/acme/infra/statuses/abc failed with 404');
    expect(err.message).not.toContain(TOKEN);
  });

  test('URL-encodes path parameters', async () => {
    const { impl, calls } = fakeFetch({});
    const gh = new RestGitHub({ token: TOKEN, fetchImpl: impl });
    await gh.comment({ owner: 'a/b', repo: 'c?d', number: 1, body: 'x' }).catch(() => {});
    expect(calls[0].url).toBe('https://api.github.com/repos/a%2Fb/c%3Fd/issues/1/comments');
  });
});
