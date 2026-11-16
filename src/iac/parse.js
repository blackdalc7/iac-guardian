'use strict';

const { parse: parseHcl } = require('@cdktf/hcl2json');
const YAML = require('yaml');

const isTerraform = (path) => path.endsWith('.tf');

// Flattens hcl2json's nested {type: {name: [config]}} layout into a list the
// Rego rules can iterate over without knowing which file a block came from.
function collectBlocks(kind, tree, file, out) {
  for (const [type, byName] of Object.entries(tree || {})) {
    for (const [name, bodies] of Object.entries(byName || {})) {
      for (const config of bodies) {
        const address = kind === 'data' ? `data.${type}.${name}` : `${type}.${name}`;
        out.push({ kind, type, name, address, file, config });
      }
    }
  }
}

async function parseTerraform(file, doc) {
  // A real HCL parser (HashiCorp's, compiled to wasm) rather than regexes:
  // policy decisions are only as sound as the document they are made on.
  const json = await parseHcl(file.path, file.content);
  collectBlocks('resource', json.resource, file.path, doc.terraform.resources);
  collectBlocks('data', json.data, file.path, doc.terraform.resources);
  for (const [name, bodies] of Object.entries(json.module || {})) {
    for (const config of bodies) doc.terraform.modules.push({ name, file: file.path, config });
  }
  for (const [name, bodies] of Object.entries(json.provider || {})) {
    doc.terraform.providers.push({ name, file: file.path, config: bodies });
  }
  // Not evaluated by policy, but tracked so the scope guard can prove a patch
  // left variables, outputs, locals and backend settings untouched.
  const { variable, output, locals, terraform } = json;
  doc.terraform.settings.push({ file: file.path, variable, output, locals, terraform });
}

function parseKubernetes(file, doc) {
  const documents = YAML.parseAllDocuments(file.content);
  for (const d of documents) {
    if (d.errors.length) throw new Error(d.errors[0].message);
    const value = d.toJS();
    if (value && typeof value === 'object' && typeof value.kind === 'string') {
      doc.kubernetes.objects.push({ file: file.path, doc: value });
    }
  }
}

/**
 * Turns a set of IaC files into the single JSON document OPA evaluates.
 * Parse failures are returned, not thrown: a patch that does not parse is an
 * expected outcome the pipeline has to report on.
 */
async function buildDocument(files) {
  const doc = {
    terraform: { resources: [], modules: [], providers: [], settings: [] },
    kubernetes: { objects: [] },
  };
  const errors = [];

  for (const file of files) {
    try {
      if (isTerraform(file.path)) await parseTerraform(file, doc);
      else parseKubernetes(file, doc);
    } catch (err) {
      errors.push({ file: file.path, message: String(err.message || err).split('\n')[0].slice(0, 300) });
    }
  }
  return { doc, errors };
}

module.exports = { buildDocument, isTerraform };
