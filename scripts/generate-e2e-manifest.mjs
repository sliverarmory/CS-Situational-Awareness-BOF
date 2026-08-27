#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = path.join(repoRoot, "src", "SA");
const portabilityManifest = JSON.parse(
  fs.readFileSync(path.join(repoRoot, "portable", "manifest.json"), "utf8"),
);
const sliverE2EPolicy = JSON.parse(
  fs.readFileSync(path.join(repoRoot, "testdata", "sliver-bof-e2e-policy.json"), "utf8"),
);
const portableCommands = portabilityManifest.command_sets?.portable;
if (!Array.isArray(portableCommands) || portableCommands.length === 0 ||
    portableCommands.some((command) => typeof command !== "string" || command.length === 0) ||
    new Set(portableCommands).size !== portableCommands.length) {
  throw new Error("portable/manifest.json must contain a non-empty, unique portable command list");
}
const windowsCommands = fs.readdirSync(sourceRoot, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

const windowsOnlyCommands = portabilityManifest.command_sets?.["windows-only"];
if (!Array.isArray(windowsOnlyCommands) ||
    windowsOnlyCommands.some((command) => typeof command !== "string" || command.length === 0) ||
    new Set(windowsOnlyCommands).size !== windowsOnlyCommands.length) {
  throw new Error("portable/manifest.json must contain a unique Windows-only command list");
}
const classifiedCommands = [...portableCommands, ...windowsOnlyCommands].sort();
if (new Set(classifiedCommands).size !== classifiedCommands.length ||
    JSON.stringify(classifiedCommands) !== JSON.stringify(windowsCommands)) {
  throw new Error("portable and Windows-only command sets must exactly partition src/SA");
}

if (sliverE2EPolicy.schema_version !== 1 ||
    typeof sliverE2EPolicy.manifest_path !== "string" ||
    sliverE2EPolicy.manifest_path.length === 0 ||
    path.isAbsolute(sliverE2EPolicy.manifest_path) ||
    sliverE2EPolicy.manifest_path.split(/[\\/]/).includes("..") ||
    !/^[0-9a-f]{40}$/.test(sliverE2EPolicy.sliver_version ?? "")) {
  throw new Error("testdata/sliver-bof-e2e-policy.json has invalid top-level metadata");
}
const sliverE2EWindowsCommands = sliverE2EPolicy.windows?.tested;
const domainRequiredWindowsCommands = sliverE2EPolicy.windows?.domain_required;
const excludedWindowsEntries = sliverE2EPolicy.windows?.excluded;
if (!Array.isArray(sliverE2EWindowsCommands) ||
    !Array.isArray(domainRequiredWindowsCommands) ||
    !Array.isArray(excludedWindowsEntries) ||
    sliverE2EWindowsCommands.some((command) => typeof command !== "string" || command.length === 0) ||
    domainRequiredWindowsCommands.some((command) => typeof command !== "string" || command.length === 0) ||
    excludedWindowsEntries.some((entry) =>
      typeof entry?.name !== "string" || entry.name.length === 0 ||
      typeof entry?.reason !== "string" || entry.reason.length === 0)) {
  throw new Error("testdata/sliver-bof-e2e-policy.json has an invalid Windows policy");
}
const excludedWindowsCommands = excludedWindowsEntries.map((entry) => entry.name);
const classifiedE2EWindowsCommands = [
  ...sliverE2EWindowsCommands,
  ...domainRequiredWindowsCommands,
  ...excludedWindowsCommands,
];
if (new Set(classifiedE2EWindowsCommands).size !== classifiedE2EWindowsCommands.length ||
    classifiedE2EWindowsCommands.some((command) => !windowsCommands.includes(command)) ||
    JSON.stringify([...classifiedE2EWindowsCommands].sort()) !== JSON.stringify(windowsCommands) ||
    JSON.stringify([...sliverE2EWindowsCommands].sort()) !== JSON.stringify(sliverE2EWindowsCommands) ||
    portableCommands.some((command) => !sliverE2EWindowsCommands.includes(command)) ||
    domainRequiredWindowsCommands.some((command) => !windowsOnlyCommands.includes(command))) {
  throw new Error("Sliver E2E tested, domain-required, and excluded sets must uniquely partition Windows commands; tested commands must be sorted and include every portable command");
}

const targets = portabilityManifest.targets;
if (!Array.isArray(targets) || targets.length === 0) {
  throw new Error("portable/manifest.json must contain a non-empty target list");
}
const targetKeys = targets.map((target) => `${target.goos}/${target.goarch}`);
if (new Set(targetKeys).size !== targetKeys.length ||
    targets.some((target) =>
      typeof target.goos !== "string" || target.goos.length === 0 ||
      typeof target.goarch !== "string" || target.goarch.length === 0 ||
      typeof target.format !== "string" || target.format.length === 0 ||
      typeof target.machine !== "string" || target.machine.length === 0 ||
      !["all-upstream", "portable"].includes(target.commands) ||
      typeof target.publish !== "boolean")) {
  throw new Error("portable/manifest.json contains an invalid or duplicate target");
}
if (targets.some((target) =>
  (target.goos === "windows") !== (target.commands === "all-upstream"))) {
  throw new Error("Windows targets must use all-upstream and Unix targets must use portable");
}

const expectedPublishedTargets = [
  "darwin/amd64", "darwin/arm64",
  "linux/386", "linux/amd64", "linux/arm64",
  "windows/386", "windows/amd64", "windows/arm64",
];
const expectedCorpusOnlyTargets = ["linux/arm", "linux/ppc64le", "linux/riscv64"];
const publishedTargets = targets.filter((target) => target.publish).map((target) => `${target.goos}/${target.goarch}`).sort();
const corpusOnlyTargets = targets.filter((target) => !target.publish).map((target) => `${target.goos}/${target.goarch}`).sort();
if (JSON.stringify(publishedTargets) !== JSON.stringify(expectedPublishedTargets) ||
    JSON.stringify(corpusOnlyTargets) !== JSON.stringify(expectedCorpusOnlyTargets)) {
  throw new Error("portable target publication policy does not match the supported matrix");
}

const variable = (name) => "${" + name + "}";
const fixtureFile = variable("FIXTURE_FILE");
const fixtureDir = variable("FIXTURE_DIR");

const explicitArguments = {
  cacls: [{ type: "wstring", value: fixtureFile }],
  dir: [{ type: "string", value: fixtureDir }, { type: "int16", value: 0 }],
  findLoadedModule: [
    { type: "string", value: "kernel32.dll" },
    { type: "string", value: "" },
  ],
  ldapsearch: [
    { type: "string", value: "(objectClass=*)" },
    { type: "string", value: "cn" },
    { type: "int32", value: 1 },
    { type: "int32", value: 3 },
    { type: "string", value: "localhost" },
    { type: "string", value: "" },
    { type: "int32", value: 0 },
  ],
  netuserenum: [
    { type: "int32", value: 0 },
    { type: "int32", value: 1 },
  ],
  md5: [{ type: "string", value: fixtureFile }],
  netgroup: [
    { type: "int16", value: 0 },
    { type: "wstring", value: "" },
    { type: "wstring", value: "" },
  ],
  netuse: [
    { type: "int16", value: 2 },
    { type: "wstring", value: "" },
  ],
  netuser: [
    { type: "wstring", value: "Administrator" },
    { type: "wstring", value: "" },
  ],
  nonpagedldapsearch: [
    { type: "string", value: "(objectClass=*)" },
    { type: "string", value: "cn" },
    { type: "int32", value: 1 },
    { type: "string", value: "localhost" },
    { type: "string", value: "" },
  ],
  nslookup: [
    { type: "string", value: "localhost" },
    { type: "string", value: "" },
    { type: "int16", value: 1 },
  ],
  probe: [
    { type: "string", value: "127.0.0.1" },
    { type: "int32", value: 1 },
    { type: "int32", value: 1 },
  ],
  reg_query: [
    { type: "string", value: "" },
    { type: "int32", value: 2 },
    { type: "string", value: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" },
    { type: "string", value: "ProductName" },
    { type: "int32", value: 0 },
  ],
  sc_qc: [{ type: "string", value: "" }, { type: "string", value: "EventLog" }],
  sc_qdescription: [{ type: "string", value: "" }, { type: "string", value: "EventLog" }],
  sc_qfailure: [{ type: "string", value: "" }, { type: "string", value: "EventLog" }],
  sc_qtriggerinfo: [{ type: "string", value: "" }, { type: "string", value: "EventLog" }],
  schtasksquery: [
    { type: "wstring", value: "" },
    { type: "wstring", value: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag" },
  ],
  sha1: [{ type: "string", value: fixtureFile }],
  sha256: [{ type: "string", value: fixtureFile }],
  sha512: [{ type: "string", value: fixtureFile }],
  vssenum: [
    { type: "wstring", value: "localhost" },
    { type: "wstring", value: "C$" },
  ],
  windowlist: [{ type: "int32", value: 1 }],
  wmi_query: [
    { type: "wstring", value: "" },
    { type: "wstring", value: "ROOT\\CIMV2" },
    { type: "wstring", value: "SELECT Caption FROM Win32_OperatingSystem" },
    { type: "wstring", value: "ROOT\\CIMV2" },
  ],
};

const portableExplicitArguments = {
  cacls: [{ type: "wstring", value: fixtureFile }],
  findLoadedModule: [
    { type: "string", value: "lib" },
    { type: "string", value: "" },
  ],
  listmods: [{ type: "int32", value: 0 }],
  netlocalgroup: [
    { type: "int16", value: 0 },
    { type: "wstring", value: "" },
    { type: "wstring", value: "" },
  ],
  netloggedon: [{ type: "wstring", value: "" }],
  netloggedon2: [{ type: "wstring", value: "" }],
  netstat: [{ type: "int32", value: 4369 }],
  netuser: [
    { type: "wstring", value: "" },
    { type: "wstring", value: "" },
  ],
  netuserenum: [
    { type: "int32", value: 0 },
    { type: "int32", value: 1 },
  ],
  nslookup: explicitArguments.nslookup,
  probe: explicitArguments.probe,
  tasklist: [{ type: "wstring", value: "" }],
};

const argumentType = (type) => {
  if (type === "integer") return "int32";
  if (type === "short") return "int16";
  if (type === "string" || type === "wstring") return type;
  throw new Error(`unsupported extension argument type ${type}`);
};

function fallbackValue(command, argument) {
  if (argument.default !== undefined && argument.default !== null) return argument.default;
  if (argument.type === "integer" || argument.type === "short") {
    if (argument.name === "port") return 1;
    if (argument.name === "timeout") return 1;
    return 0;
  }
  if (argument.name === "filepath") return fixtureFile;
  if (argument.name === "targetdir") return fixtureDir;
  if (argument.name === "modname") return "kernel32.dll";
  if (argument.name === "servicename") return "EventLog";
  if (argument.name === "taskname") return "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag";
  if (argument.name === "query") {
    return command.includes("ldap") ? "(objectClass=*)" : "SELECT Caption FROM Win32_OperatingSystem";
  }
  if (argument.name === "namespace" || argument.name === "resource") return "ROOT\\CIMV2";
  if (argument.name === "hostname" && argument.optional === false) return "localhost";
  if (argument.name === "host") return "127.0.0.1";
  if (argument.name === "username") return "Administrator";
  return "";
}

function windowsArguments(command, arch) {
  if (command === "adv_audit_policies") {
    return [{ type: "int32", value: arch === "386" ? 1 : 0 }];
  }
  if (explicitArguments[command]) return explicitArguments[command];
  const extension = JSON.parse(fs.readFileSync(path.join(sourceRoot, command, "extension.json"), "utf8"));
  const metadata = extension.commands?.[0] ?? extension;
  return (metadata.arguments ?? []).map((argument) => ({
    type: argumentType(argument.type),
    value: fallbackValue(command, argument),
  }));
}

const digestExpectations = {
  md5: "b9b3a37829baa40ee941e901aab8671b",
  sha1: "a7251fd58489a73e2823956299fb6fa7c250d393",
  sha256: "74ccef2214ea8b89387bf7363ab01a4caccbb502417c0af7e42a578d67f1c9cb",
  sha512: "2a429bf6031684e95a16222aeb20f60edf30e67bec73e1a1fe47ba2e0a2b03b0be567830989d89c271ccd00896e820165034ac8b36e1056deb76c5efd8a12e57",
};

function expectation(command, os) {
  if (digestExpectations[command]) {
    return { types: [0, 13], contains_any: [digestExpectations[command]], case_insensitive: true, min_callbacks: 1 };
  }
  if (command === "arp") {
    return {
      types: [0, 13],
      contains_any: os === "windows" ? [] : ["ARP table:"],
      min_callbacks: os === "windows" ? 0 : 1,
    };
  }
  if (command === "dir") return { types: [0, 13], contains_all: ["Contents of", "marker.txt"], min_callbacks: 1 };
  if (command === "probe") return { types: [0, 13, 30, 32], contains_all: ["OPEN"], min_callbacks: 1 };
  if (command === "env") return { types: [0, 13], contains_any: ["="], min_callbacks: 1 };
  if (command === "whoami") return { types: [0, 13], contains_any: os === "windows" ? [] : ["uid="], min_callbacks: 1 };
  if (command === "uptime") return { types: [0, 13], contains_any: [os === "windows" ? "Uptime" : "uptime_seconds="], min_callbacks: 1 };
  if (os !== "windows") {
    if (command === "cacls") {
      return { types: [0, 13], contains_all: ["Exists: yes", "Total entries: 1"], min_callbacks: 1 };
    }
    if (command === "netuser") {
      return { types: [0, 13], contains_all: ["Local POSIX user information:", "Total users: 1"], min_callbacks: 1 };
    }
    if (command === "ipconfig") {
      return { types: [0, 13], contains_all: ["Network interfaces:", "hostname:", "Resolver configuration:"], min_callbacks: 1 };
    }
    if (command === "tasklist" && os === "linux") {
      return { types: [0, 13], contains_all: ["Processes:", "Name:\t", "Pid:\t", "PPid:\t"], min_callbacks: 1 };
    }
    const portableMarkers = {
      enumLocalSessions: "Local sessions:",
      findLoadedModule: "Current-process loaded module matches:",
      listmods: "Loaded modules:",
      locale: "Locale:",
      netlocalgroup: "Local groups:",
      netloggedon: "Users logged on (local POSIX host):",
      netloggedon2: "Structured local POSIX sessions:",
      netstat: "Network connections:",
      netuserenum: "Local POSIX users:",
      nslookup: "DNS results for",
      resources: "System resources:",
      routeprint: "Routing table:",
      tasklist: "Processes:",
    };
    if (portableMarkers[command]) {
      return { types: [0, 13], contains_any: [portableMarkers[command]], min_callbacks: 1 };
    }
  }
  if (os === "windows" && ["driversigs", "netloggedon2", "netview", "notepad", "windowlist"].includes(command)) {
    return { types: [0, 13, 30, 32], contains_any: [], min_callbacks: 0 };
  }
  return { types: [0, 13, 30, 32], contains_any: [], min_callbacks: 1 };
}

const artifacts = [];
for (const target of targets) {
  const commands = target.commands === "all-upstream" ? windowsCommands : portableCommands;
  for (const command of commands) {
    if (target.commands === "all-upstream") {
      artifacts.push({
        name: command,
        os: target.goos,
        arch: target.goarch,
        path: `dist/${target.goos}/${target.goarch}/${command}.o`,
        args: windowsArguments(command, target.goarch),
        ...(command === "probe" ? { tcp_listener: { port_argument: 1 } } : {}),
        expect: expectation(command, target.goos),
      });
    } else {
      let args = [];
      if (command === "dir") {
        args = [{ type: "string", value: fixtureDir }, { type: "int16", value: 0 }];
      } else if (digestExpectations[command]) {
        args = [{ type: "string", value: fixtureFile }];
      } else if (portableExplicitArguments[command]) {
        args = portableExplicitArguments[command];
      }
      artifacts.push({
        name: command,
        os: target.goos,
        arch: target.goarch,
        path: `dist/${target.goos}/${target.goarch}/${command}.o`,
        args,
        ...(command === "probe" ? { tcp_listener: { port_argument: 1 } } : {}),
        expect: expectation(command, target.goos),
      });
    }
  }
}

const manifest = {
  version: 1,
  entrypoint: "go",
  fixtures: {
    file: { variable: "FIXTURE_FILE", contents_utf8: "reflektor-bof-e2e\n" },
    directory: { variable: "FIXTURE_DIR", files: { "marker.txt": "reflektor-bof-e2e\n" } },
  },
  artifacts,
};

function escapeRegexp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const windowsSliverActionExpectations = {
  aadjoininfo: { output: { matches: ["(?:AAD/Entra ID Join Info|Host is not cloud joined)"] } },
  adv_audit_policies: { output: { matches: ["(?:SUCCESS\\.|No audit\\.csv files)"] } },
  cacls: { output: { contains: ["FIXTURE_FILE.txt"] } },
  enumLocalSessions: { output: { contains: ["Enumerating sessions for local system:"] } },
  enum_filter_driver: { output: { contains: ["SUCCESS."] } },
  env: { output: { contains: ["Gathering Process Environment Variables:"] } },
  findLoadedModule: {
    output: { matches: ["(?i:kernel32\\.dll|Successfully enumerated all processes)"] },
  },
  "get-netsession": { output: { contains: ["entries enumerated"] } },
  "get-netsession2": { output: { contains: ["Resolving client IPs to hostnames using"] } },
  get_password_policy: { output: { contains: ["Minimum password length:"] } },
  get_session_info: { output: { contains: ["UserName:"] } },
  hostname: { output: { contains: ["Computer Name:"] } },
  ipconfig: { output: { contains: ["Windows IP Configuration"] } },
  list_firewall_rules: {
    output: { contains: ["The number of rules in the Windows Firewall"] },
  },
  listdns: { output: { matches: ["(?:Cache record:|No results found)"] } },
  listmods: { output: { contains: ["Printing modules of process ID:"] } },
  locale: { output: { contains: ["Locale:"] } },
  netlocalgroup: { output: { matches: ["Name:\\s+"] } },
  netlocalgroup2: { output: { contains: ["Querying Remote Desktop Users"] } },
  netloggedon: { output: { contains: ["Users logged on:"] } },
  netshares: { output: { contains: ["Share:              Remark:"] } },
  netstat: { output: { contains: ["Active Connections"] } },
  nettime: { output: { contains: ["Local time (GMT"] } },
  netuptime: { output: { contains: ["ServerName:"] } },
  netuse: { output: { contains: ["The command completed successfully"] } },
  netuser: { output: { contains: ["User name:"] } },
  netuserenum: { output: { matches: ["-- [^\\r\\n]+"] } },
  nslookup: { output: { matches: ["A localhost "] } },
  reg_query: { output: { contains: ["ProductName"] } },
  regsession: { output: { contains: ["Querying local registry"] } },
  resources: { output: { contains: ["Memory Used:"] } },
  routeprint: { output: { contains: ["Interface List"] } },
  sc_enum: { output: { contains: ["SERVICE_NAME:"] } },
  sc_qc: { output: { contains: ["SERVICE_NAME: EventLog"] } },
  sc_qfailure: { output: { contains: ["SERVICE_NAME: EventLog"] } },
  sc_qtriggerinfo: {
    output: { matches: ["(?:SERVICE_NAME: EventLog|The service EventLog has not registered)"] },
  },
  sc_query: { output: { contains: ["SERVICE_NAME: EventLog"] } },
  schtasksenum: { output: { matches: ["Task [0-9]+"] } },
  schtasksquery: { output: { contains: ["Name:"] } },
  tasklist: { output: { matches: ["System\\s+[0-9]+"] } },
  useridletime: { output: { contains: ["Current User idle time:"] } },
  vol: { output: { contains: ["Volume in drive"] } },
  vssenum: { output: { contains: ["Target = "] } },
  whoami: { output: { contains: ["UserName", "SID"] } },
  wmi_query: { output: { matches: ["(?i:Microsoft Windows)"] } },
};

// These commands can complete successfully with no output on a clean, headless
// Windows runner. Keep the smoke-test set explicit so newly added BOFs cannot
// silently fall back to success-only coverage.
const windowsSliverActionSmokeCommands = new Set([
  "arp",
  "driversigs",
  "netloggedon2",
  "netview",
  "notepad",
  "sc_qdescription",
  "windowlist",
]);

function sliverActionExpectation(artifact) {
  if (artifact.os === "windows" && windowsSliverActionExpectations[artifact.name]) {
    return windowsSliverActionExpectations[artifact.name];
  }
  const expected = artifact.expect;
  if (artifact.name === "cat") {
    return { output: { contains: ["reflektor-bof-e2e"] } };
  }
  if (Array.isArray(expected.contains_all) && expected.contains_all.length > 0) {
    if (expected.case_insensitive) {
      return {
        output: {
          matches: expected.contains_all.map((value) => `(?i:${escapeRegexp(value)})`),
        },
      };
    }
    return { output: { contains: expected.contains_all } };
  }
  if (Array.isArray(expected.contains_any) && expected.contains_any.length > 0) {
    if (expected.contains_any.length === 1 && !expected.case_insensitive) {
      return { output: { contains: expected.contains_any } };
    }
    const alternatives = expected.contains_any.map(escapeRegexp).join("|");
    return {
      output: {
        matches: [`${expected.case_insensitive ? "(?i:" : "(?:"}${alternatives})`],
      },
    };
  }
  if (artifact.os === "windows" && !windowsSliverActionSmokeCommands.has(artifact.name)) {
    throw new Error(`Windows Sliver E2E test ${artifact.name} has no output assertion`);
  }
  return { success_only: true };
}

function sliverActionArguments(args) {
  return args.map((argument) => {
    let type;
    if (argument.type === "int32") type = "int";
    else if (argument.type === "int16") type = "short";
    else if (["string", "wstring"].includes(argument.type)) type = argument.type;
    else throw new Error(`unsupported Sliver action argument type ${argument.type}`);
    return { type, value: argument.value };
  });
}

const sliverActionSuites = targets
  .filter((target) => target.publish)
  .map((target) => {
    const commands = target.goos === "windows" ? sliverE2EWindowsCommands : portableCommands;
    const tests = commands.map((command) => {
      const artifact = artifacts.find((candidate) =>
        candidate.name === command &&
        candidate.os === target.goos &&
        candidate.arch === target.goarch);
      if (!artifact) {
        throw new Error(`missing generated artifact contract for ${target.goos}/${target.goarch}/${command}`);
      }
      return {
        name: command,
        object: artifact.path,
        ...(artifact.args.length > 0 ? { args: sliverActionArguments(artifact.args) } : {}),
        ...(artifact.tcp_listener ? { tcp_listener: artifact.tcp_listener } : {}),
        expect: sliverActionExpectation(artifact),
      };
    });
    return {
      name: `${target.goos}-${target.goarch}`,
      target: { os: target.goos, arch: target.goarch },
      tests,
    };
  });

const generatedWindowsSmokeCommands = [...new Set(sliverActionSuites
  .filter((suite) => suite.target.os === "windows")
  .flatMap((suite) => suite.tests)
  .filter((test) => test.expect.success_only)
  .map((test) => test.name))].sort();
if (JSON.stringify(generatedWindowsSmokeCommands) !==
    JSON.stringify([...windowsSliverActionSmokeCommands].sort())) {
  throw new Error("generated Windows Sliver E2E smoke tests do not match the explicit policy");
}

const sliverActionManifest = {
  schema: "sliver-bof-e2e/v1",
  sliver: { version: sliverE2EPolicy.sliver_version },
  defaults: {
    bof_executor: "reflektor",
    entrypoint: "go",
    modes: ["session", "beacon"],
    repeat: 1,
    command_timeout: "2m",
  },
  fixtures: {
    file: { variable: "FIXTURE_FILE", contents_utf8: "reflektor-bof-e2e\n" },
    directory: {
      variable: "FIXTURE_DIR",
      files: { "marker.txt": "reflektor-bof-e2e\n" },
    },
  },
  suites: sliverActionSuites,
};

const sliverActionMode = process.argv.includes("--sliver-action");
const selectedManifest = sliverActionMode ? sliverActionManifest : manifest;
const output = `${JSON.stringify(selectedManifest, null, 2)}\n`;
if (process.argv.includes("--write")) {
  const outputPath = sliverActionMode
    ? path.join(repoRoot, sliverE2EPolicy.manifest_path)
    : path.join(repoRoot, "testdata", "e2e-manifest.json");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, output);
} else {
  process.stdout.write(output);
}
