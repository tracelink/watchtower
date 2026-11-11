"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { createRequire } = require("module");

module.exports = { capture, hashPackage };

const executableExtensions = new Set([".js", ".cjs", ".mjs", ".json", ".node", ".wasm", ".jst"]);

function digest(value) {
    return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function hashFile(file) {
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.alloc(65536);
    const fd = fs.openSync(file, "r");
    try {
        let count;
        while ((count = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, count));
        return hash.digest("hex");
    } finally {
        fs.closeSync(fd);
    }
}

function included(file) {
    const parts = file.split(path.sep);
    return !parts.some(part => part.startsWith(".") || part === "node_modules")
        && executableExtensions.has(path.extname(file));
}

/** Public installed package code/data only; npm credentials and application files are excluded. */
function hashPackage(root) {
    if (fs.realpathSync(root) !== root) throw new Error("Unsupported package link");
    const entries = [];
    function walk(directory) {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
            if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
            const file = path.join(directory, entry.name);
            if (entry.isSymbolicLink()) throw new Error("Unsupported package link");
            if (entry.isDirectory()) walk(file);
            else if (included(path.relative(root, file))) {
                if (!entry.isFile()) throw new Error("Unsupported package entry");
                entries.push([path.relative(root, file).split(path.sep).join("/"), hashFile(file)]);
            }
        }
    }
    walk(root);
    if (!entries.length) throw new Error("Missing package code");
    return digest(["watchtower-node-package-v1", entries]);
}

function packageRoot(file) {
    let directory = path.dirname(file);
    while (!fs.existsSync(path.join(directory, "package.json"))) {
        const parent = path.dirname(directory);
        if (parent === directory) throw new Error("Missing package manifest");
        directory = parent;
    }
    return directory;
}

function configuredRules(selection) {
    const body = require("espree").parse(selection, { ecmaVersion: 2020 }).body;
    const assignment = body.length === 2 && body[1].expression;
    if (body[0].directive !== "use strict" || !assignment || assignment.type !== "AssignmentExpression"
        || assignment.operator !== "=" || assignment.left.type !== "MemberExpression" || assignment.left.computed
        || assignment.left.object.name !== "module" || assignment.left.property.name !== "exports") {
        throw new Error("Unsupported exported configuration");
    }
    function data(node) {
        if (node.type === "Literal") return node.value;
        if (node.type !== "ObjectExpression") throw new Error("Nonliteral exported configuration");
        const value = Object.create(null);
        for (const property of node.properties) {
            if (property.type !== "Property" || property.computed || property.method || property.shorthand
                || property.kind !== "init") throw new Error("Nonliteral exported configuration");
            const name = property.key.type === "Identifier" ? property.key.name : property.key.value;
            if (typeof name !== "string" || name in value) throw new Error("Ambiguous exported configuration");
            value[name] = data(property.value);
        }
        return value;
    }
    const ruleset = data(assignment.right).ruleset;
    if (!ruleset || !ruleset.customRules || Object.keys(ruleset.customRules).length || !ruleset.priorities
        || Object.values(ruleset.priorities).some(value => typeof value !== "number")) {
        throw new Error("Unsupported selected rules");
    }
    return Object.keys(ruleset.priorities);
}

function capture(selection) {
    try {
        // These can load code/data outside the installed engine contract. Do not hash their values.
        const overrides = ["NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA", "NODE_EXTRA_CA_CERTS", "OPENSSL_CONF"];
        if (overrides.some(name => process.env[name])
            || Object.keys(process.env).some(name => name.startsWith("LD_") || name.startsWith("DYLD_"))) {
            throw new Error("Unsupported runtime override");
        }
        const Linter = require("eslint").Linter;
        const linter = new Linter();
        const rules = Array.from(linter.getRules().keys()).sort();
        const selected = configuredRules(selection);
        if (selected.some(name => !rules.includes(name))) throw new Error("Missing selected rule");
        linter.verify("", { parserOptions: { ecmaVersion: 2020 }, rules: {} });
        if (Object.keys(require.extensions).some(extension => ![".js", ".json", ".node"].includes(extension))) {
            throw new Error("Unsupported module loader");
        }
        const eslintRoot = packageRoot(require.resolve("eslint"));
        const packages = [];
        const indices = new Map();
        function visit(root) {
            if (indices.has(root)) return indices.get(root);
            const index = packages.length;
            indices.set(root, index);
            const metadata = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
            const item = { name: metadata.name, version: metadata.version, hash: hashPackage(root), dependencies: [] };
            packages.push(item);
            const resolve = createRequire(path.join(root, "package.json"));
            const required = metadata.dependencies || {};
            const optional = metadata.optionalDependencies || {};
            const peers = metadata.peerDependencies || {};
            const dependencies = Array.from(new Set([...Object.keys(required), ...Object.keys(optional), ...Object.keys(peers)])).sort();
            for (const name of dependencies) {
                if (!/^(?:@[\w.-]+\/)?[\w.-]+$/.test(name)) throw new Error("Unsupported dependency name");
                let target;
                try {
                    try { target = resolve.resolve(name + "/package.json"); }
                    catch (_) { target = resolve.resolve(name); }
                } catch (_) {
                    if (name in optional || (name in peers && !(name in required))) {
                        item.dependencies.push([name, null]);
                        continue;
                    }
                    throw new Error("Missing runtime dependency");
                }
                item.dependencies.push([name, visit(packageRoot(target))]);
            }
            return index;
        }
        visit(eslintRoot);
        // Capture any imports not declared in package manifests as well.
        for (const file of Object.keys(require.cache).sort()) {
            if (file === __filename) continue;
            const root = packageRoot(file);
            if (!included(path.relative(root, file))) throw new Error("Unsupported loaded resource");
            visit(root);
        }
        const native = [];
        const systemBuild = process.platform === "darwin"
            ? require("child_process").execFileSync("/usr/bin/sw_vers", ["-buildVersion"], { encoding: "utf8" }).trim()
            : os.version();
        for (const file of process.report.getReport().sharedObjects) {
            // macOS system images live in the OS shared cache; bind them to the actual OS build.
            if (process.platform === "darwin" && (file.startsWith("/usr/lib/") || file.startsWith("/System/Library/"))) continue;
            if (/^linux-vdso\.so\./.test(file)) continue;
            if (!path.isAbsolute(file) || !fs.statSync(file).isFile()) throw new Error("Unsupported native runtime");
            native.push(hashFile(file));
        }
        const locale = Intl.DateTimeFormat().resolvedOptions();
        const eslintVersion = JSON.parse(fs.readFileSync(path.join(eslintRoot, "package.json"), "utf8")).version;
        const fingerprint = digest(["watchtower-eslint-runtime-v1", process.versions, hashFile(process.execPath),
            process.platform, process.arch, os.release(), systemBuild, locale.locale, locale.timeZone, native, packages]);
        return JSON.stringify({ schema: 1, complete: true, nodeVersion: process.version, eslintVersion, fingerprint, rules, selected });
    } catch (_) {
        // Failure details can contain private installation paths/configuration. Persist none of them.
        return JSON.stringify({ schema: 1, complete: false });
    }
}
