import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

// Render the actual CreateVault component with its state preset (name, members, threshold).
function render(members, threshold) {
  const source = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
  const page = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const form = page.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'CreateVault');
  assert.ok(form);
  const { outputText } = ts.transpileModule(form.getText(page), { compilerOptions: { jsx: ts.JsxEmit.React } });
  const load = new Function('React', 'useState', 'api', 'rememberVaultSlot', 'BackLink', 'GlassCard', 'Btn', 'ErrMsg',
    `${outputText}\nreturn CreateVault;`);
  const preset = ['Friends', members, threshold];
  let call = 0;
  const useState = (initial) => React.useState(call < preset.length ? preset[call++] : initial);
  const CreateVault = load(React, useState, null, null, () => null, 'section', 'button', () => null);
  const html = renderToStaticMarkup(React.createElement(CreateVault, {}));
  const selects = [...html.matchAll(/<select[^>]*>(.*?)<\/select>/g)]
    .map(([, options]) => [...options.matchAll(/value="(\d+)"/g)].map(([, n]) => Number(n)));
  return { html, members: selects[0], thresholds: selects[1] };
}

// The host accepts 2 <= t < n <= 16 (`valid_policy`); the form offers only that.
test('the create-vault form offers only thresholds below the member count', () => {
  const three = render(3, 2);
  assert.deepEqual(three.members, Array.from({ length: 14 }, (_, i) => i + 3));
  assert.deepEqual(three.thresholds, [2]);
  assert.deepEqual(render(5, 2).thresholds, [2, 3, 4]);
  assert.deepEqual(render(16, 2).thresholds.at(-1), 15);
  // A threshold left over from a larger member count drops to the highest allowed.
  assert.match(render(3, 3).html, /2 of 3 approvals/);
});
