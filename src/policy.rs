//! Trust decisions. Everything here works on a `Caller` snapshot and a parsed
//! policy, with no FUSE or filesystem state, so it can later run inside a
//! separate privileged process unchanged.

use std::path::Path;

use anyhow::{Context, Result, bail};
use glob::Pattern;
use serde::{Deserialize, Serialize};

use crate::caller::{Caller, ProcInfo, SessionKind};

/// Ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum View {
    Real,
    Redacted,
    Canary,
}

impl View {
    pub fn as_str(self) -> &'static str {
        match self {
            View::Real => "real",
            View::Redacted => "redacted",
            View::Canary => "canary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub view: View,
    pub rule: String,
}

pub const BUILTINS: &[&str] = &["package-install", "ai-agent"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    defaults: Defaults,
    #[serde(default, rename = "rule")]
    rules: Vec<RuleSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Defaults {
    #[serde(default = "default_unknown")]
    unknown: View,
    #[serde(default)]
    disable_builtin: Vec<String>,
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            unknown: default_unknown(),
            disable_builtin: Vec::new(),
        }
    }
}

fn default_unknown() -> View {
    View::Redacted
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    name: Option<String>,
    view: View,
    exe: Option<String>,
    cgroup: Option<String>,
    session_root: Option<String>,
    ancestor_exe: Option<String>,
    cmdline: Option<String>,
    ancestor_cmdline: Option<String>,
}

#[derive(Debug)]
struct Rule {
    name: String,
    view: View,
    exe: Option<Pattern>,
    cgroup: Option<Pattern>,
    session_root: Option<SessionKind>,
    ancestor_exe: Option<Pattern>,
    cmdline: Option<Pattern>,
    ancestor_cmdline: Option<Pattern>,
}

#[derive(Debug)]
pub struct Policy {
    unknown: View,
    package_install: bool,
    ai_agent: bool,
    rules: Vec<Rule>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            unknown: View::Redacted,
            package_install: true,
            ai_agent: true,
            rules: Vec::new(),
        }
    }
}

impl Policy {
    pub fn load(path: &Path) -> Result<Policy> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        Policy::parse(&raw).with_context(|| format!("in policy {}", path.display()))
    }

    pub fn parse(raw: &str) -> Result<Policy> {
        let file: PolicyFile = toml::from_str(raw)?;
        if file.defaults.unknown == View::Real {
            bail!("defaults.unknown can't be \"real\"; unknown callers get redacted or canary");
        }
        for b in &file.defaults.disable_builtin {
            if !BUILTINS.contains(&b.as_str()) {
                bail!("unknown builtin {b:?}; known: {}", BUILTINS.join(", "));
            }
        }
        let mut rules = Vec::new();
        for (i, spec) in file.rules.into_iter().enumerate() {
            let name = spec.name.clone().unwrap_or_else(|| format!("rule {}", i + 1));
            rules.push(compile(spec, &name).with_context(|| format!("rule {name:?}"))?);
        }
        let disabled = |n: &str| file.defaults.disable_builtin.iter().any(|b| b == n);
        Ok(Policy {
            unknown: file.defaults.unknown,
            package_install: !disabled("package-install"),
            ai_agent: !disabled("ai-agent"),
            rules,
        })
    }

    /// For callers that couldn't be pinned to a process.
    pub fn decide_unidentified(&self) -> View {
        self.unknown.max(View::Redacted)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn decide(&self, c: &Caller) -> Decision {
        let mut d = self
            .rules
            .iter()
            .find(|r| r.matches(c))
            .map(|r| Decision {
                view: r.view,
                rule: r.name.clone(),
            })
            .unwrap_or_else(|| Decision {
                view: self.unknown,
                rule: "default".into(),
            });
        // Builtins only ever tighten. A user rule that already says canary
        // stays canary.
        if d.view < View::Redacted {
            if self.package_install && is_package_install(c) {
                d = Decision {
                    view: View::Redacted,
                    rule: "builtin:package-install".into(),
                };
            } else if self.ai_agent && is_ai_agent(c) {
                d = Decision {
                    view: View::Redacted,
                    rule: "builtin:ai-agent".into(),
                };
            }
        }
        d
    }
}

fn compile(spec: RuleSpec, name: &str) -> Result<Rule> {
    let pat = |s: &Option<String>| -> Result<Option<Pattern>> {
        s.as_deref()
            .map(|p| Pattern::new(p).with_context(|| format!("bad pattern {p:?}")))
            .transpose()
    };
    let session_root = match spec.session_root.as_deref() {
        None => None,
        Some("sshd") => Some(SessionKind::Sshd),
        Some("tmux") => Some(SessionKind::Tmux),
        Some("vscode-server") => Some(SessionKind::VscodeServer),
        Some("systemd-user") => Some(SessionKind::SystemdUser),
        Some(other) => {
            bail!("session_root {other:?} is not one of sshd, tmux, vscode-server, systemd-user")
        }
    };
    let rule = Rule {
        name: name.to_string(),
        view: spec.view,
        exe: pat(&spec.exe)?,
        cgroup: pat(&spec.cgroup)?,
        session_root,
        ancestor_exe: pat(&spec.ancestor_exe)?,
        cmdline: pat(&spec.cmdline)?,
        ancestor_cmdline: pat(&spec.ancestor_cmdline)?,
    };
    let strong = rule.exe.is_some()
        || rule.cgroup.is_some()
        || rule.ancestor_exe.is_some()
        || matches!(rule.session_root, Some(k) if k != SessionKind::VscodeServer);
    let weak = rule.cmdline.is_some()
        || rule.ancestor_cmdline.is_some()
        || rule.session_root == Some(SessionKind::VscodeServer);
    if !strong && !weak {
        bail!("rule has no matchers");
    }
    if rule.view == View::Real && !strong {
        bail!(
            "view = \"real\" needs exe, cgroup, ancestor_exe or session_root \
             (sshd, tmux, systemd-user); cmdline can be forged and vscode-server \
             lives in a user-writable path"
        );
    }
    Ok(rule)
}

impl Rule {
    fn matches(&self, c: &Caller) -> bool {
        if let Some(p) = &self.exe
            && !c.proc.exe.as_deref().is_some_and(|e| p.matches(e))
        {
            return false;
        }
        if let Some(p) = &self.cgroup
            && !c.proc.cgroup.as_deref().is_some_and(|g| p.matches(g))
        {
            return false;
        }
        if let Some(kind) = self.session_root {
            let ok = c.session_root.as_ref().is_some_and(|r| {
                r.kind == kind && (r.verified || kind == SessionKind::VscodeServer)
            });
            if !ok {
                return false;
            }
        }
        if let Some(p) = &self.ancestor_exe
            && !c
                .ancestry
                .iter()
                .any(|a| a.exe.as_deref().is_some_and(|e| p.matches(e)))
        {
            return false;
        }
        if let Some(p) = &self.cmdline
            && !p.matches(&c.proc.cmdline_untrusted.join(" "))
        {
            return false;
        }
        if let Some(p) = &self.ancestor_cmdline
            && !c
                .ancestry
                .iter()
                .any(|a| p.matches(&a.cmdline_untrusted.join(" ")))
        {
            return false;
        }
        if self.view == View::Real {
            // Every matcher hit, but real also needs one the caller couldn't
            // have arranged. A cgroup the user can move processes into doesn't
            // count.
            let strong = self.exe.is_some()
                || self.ancestor_exe.is_some()
                || matches!(self.session_root, Some(k) if k != SessionKind::VscodeServer)
                || (self.cgroup.is_some() && !c.cgroup_user_movable);
            if !strong {
                return false;
            }
        }
        true
    }
}

fn lineage(c: &Caller) -> impl Iterator<Item = &ProcInfo> {
    std::iter::once(&c.proc).chain(c.ancestry.iter())
}

fn base(s: &str) -> &str {
    let s = s.strip_suffix(" (deleted)").unwrap_or(s);
    let b = s.rsplit('/').next().unwrap_or(s);
    b.strip_suffix(".js")
        .or_else(|| b.strip_suffix(".cjs"))
        .or_else(|| b.strip_suffix(".mjs"))
        .unwrap_or(b)
}

fn env_value<'a>(c: &'a Caller, key: &str) -> Option<&'a str> {
    c.env_hints.iter().find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

const NPM_INSTALL_EVENTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

/// Matches on argv and environment, which the process controls. That's fine
/// for a rule that only ever takes access away.
fn is_package_install(c: &Caller) -> bool {
    if env_value(c, "npm_lifecycle_event").is_some_and(|e| NPM_INSTALL_EVENTS.contains(&e))
        || env_value(c, "PIP_BUILD_TRACKER").is_some()
        || (env_value(c, "OUT_DIR").is_some() && env_value(c, "CARGO_MANIFEST_DIR").is_some())
    {
        return true;
    }
    lineage(c).any(|p| {
        if let Some(exe) = p.exe.as_deref() {
            if base(exe) == "rustc" {
                return true;
            }
            if exe.contains("/build/") && base(exe).starts_with("build-script-") {
                return true;
            }
        }
        argv_is_install(&p.cmdline_untrusted)
    })
}

pub fn argv_is_install(argv: &[String]) -> bool {
    // Interpreters put the tool in argv[1]: node /usr/bin/npm install.
    let Some(tool_at) = argv.iter().take(3).position(|a| {
        matches!(
            base(a),
            "npm"
                | "npm-cli"
                | "pnpm"
                | "yarn"
                | "bun"
                | "npx"
                | "pnpx"
                | "bunx"
                | "pip"
                | "pip3"
                | "uv"
                | "poetry"
                | "pipx"
        )
    }) else {
        return argv.windows(2).any(|w| w[0] == "-m" && w[1] == "pip")
            && argv.iter().any(|a| a == "install");
    };
    let tool = base(&argv[tool_at]);
    let rest: Vec<&str> = argv[tool_at + 1..]
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    match tool {
        "npx" | "pnpx" | "bunx" => true,
        "yarn" if rest.is_empty() => true,
        "uv" => rest.first() == Some(&"sync") || rest.starts_with(&["pip", "install"]),
        "pipx" => matches!(rest.first(), Some(&"install") | Some(&"run")),
        _ => matches!(
            rest.first(),
            Some(&"install")
                | Some(&"i")
                | Some(&"ci")
                | Some(&"add")
                | Some(&"rebuild")
                | Some(&"dlx")
                | Some(&"exec")
        ),
    }
}

const AGENT_BINARIES: &[&str] = &[
    "claude",
    "codex",
    "gemini",
    "aider",
    "cursor-agent",
    "opencode",
    "goose",
    "amp",
    "crush",
    "qwen",
];

const AGENT_PACKAGES: &[&str] = &[
    "@anthropic-ai/claude-code",
    "@openai/codex",
    "@google/gemini-cli",
    "@sourcegraph/amp",
    "opencode-ai",
];

const AGENT_ENV: &[&str] = &[
    "CLAUDECODE",
    "AI_AGENT",
    "GEMINI_CLI",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
];

fn is_ai_agent(c: &Caller) -> bool {
    if AGENT_ENV.iter().any(|k| env_value(c, k).is_some()) {
        return true;
    }
    lineage(c).any(|p| {
        p.exe
            .as_deref()
            .is_some_and(|e| AGENT_BINARIES.contains(&base(e)))
            || p.cmdline_untrusted
                .iter()
                .take(2)
                .any(|a| AGENT_BINARIES.contains(&base(a)))
            || p
                .cmdline_untrusted
                .iter()
                .take(3)
                .any(|a| AGENT_PACKAGES.iter().any(|pkg| a.contains(pkg)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::{Identity, SessionRoot};

    fn proc(pid: i32, exe: &str, argv: &[&str], cgroup: &str) -> ProcInfo {
        ProcInfo {
            pid,
            start_time: 100,
            ppid: pid - 1,
            exe: Some(exe.into()),
            comm_untrusted: base(exe).into(),
            cmdline_untrusted: argv.iter().map(|s| s.to_string()).collect(),
            cgroup: Some(cgroup.into()),
        }
    }

    fn caller(p: ProcInfo, ancestry: Vec<ProcInfo>) -> Caller {
        Caller {
            tid: p.pid,
            identity: Identity {
                tgid: p.pid,
                start_time: p.start_time,
            },
            proc: p,
            ancestry,
            session_root: None,
            cgroup_user_movable: false,
            reached_init: false,
            env_hints: Vec::new(),
        }
    }

    const CG: &str = "/user.slice/user-1000.slice/session-2.scope";

    #[test]
    fn unknown_is_redacted() {
        let c = caller(proc(10, "/usr/bin/cat", &["cat", ".env"], CG), vec![]);
        let d = Policy::default().decide(&c);
        assert_eq!(d.view, View::Redacted);
        assert_eq!(d.rule, "default");
    }

    #[test]
    fn exe_rule_grants_real() {
        let p = Policy::parse(
            r#"
            [[rule]]
            name = "editor"
            view = "real"
            exe = "/usr/bin/nvim"
            "#,
        )
        .unwrap();
        let c = caller(proc(10, "/usr/bin/nvim", &["nvim"], CG), vec![]);
        assert_eq!(p.decide(&c).view, View::Real);
        let c = caller(proc(10, "/tmp/nvim", &["/usr/bin/nvim"], CG), vec![]);
        assert_eq!(p.decide(&c).view, View::Redacted);
    }

    #[test]
    fn cmdline_alone_cannot_grant_real() {
        let err = Policy::parse(
            r#"
            [[rule]]
            view = "real"
            cmdline = "node server.js"
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cmdline can be forged"));
        let err = Policy::parse(
            r#"
            [[rule]]
            view = "real"
            session_root = "vscode-server"
            "#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("vscode-server"));
        // Restricting on cmdline is fine.
        Policy::parse(
            r#"
            [[rule]]
            view = "canary"
            cmdline = "*curl*"
            "#,
        )
        .unwrap();
    }

    #[test]
    fn rejects_real_default_and_unknown_fields() {
        assert!(Policy::parse("[defaults]\nunknown = \"real\"\n").is_err());
        assert!(Policy::parse("[[rule]]\nview = \"real\"\nexe_path = \"/x\"\n").is_err());
        assert!(Policy::parse("[defaults]\ndisable_builtin = [\"nope\"]\n").is_err());
    }

    #[test]
    fn npm_install_beats_user_allow() {
        let p = Policy::parse(
            r#"
            [[rule]]
            view = "real"
            exe = "/usr/bin/node"
            "#,
        )
        .unwrap();
        let npm = proc(9, "/usr/bin/node", &["npm", "install"], CG);
        let script = proc(10, "/usr/bin/node", &["node", "postinstall.js"], CG);
        let c = caller(script.clone(), vec![npm]);
        let d = p.decide(&c);
        assert_eq!(d.view, View::Redacted);
        assert_eq!(d.rule, "builtin:package-install");
        // The same node outside an install gets the rule.
        let dev = proc(9, "/usr/bin/node", &["npm", "run", "dev"], CG);
        assert_eq!(p.decide(&caller(script, vec![dev])).view, View::Real);
    }

    #[test]
    fn npm_lifecycle_env_survives_reparenting() {
        let p = Policy::parse("[[rule]]\nview = \"real\"\ncgroup = \"/user.slice/**\"\n").unwrap();
        let mut c = caller(proc(10, "/usr/bin/node", &["node", "x.js"], CG), vec![]);
        assert_eq!(p.decide(&c).view, View::Real);
        c.env_hints = vec!["npm_lifecycle_event=postinstall".into()];
        assert_eq!(p.decide(&c).view, View::Redacted);
        c.env_hints = vec!["npm_lifecycle_event=dev".into()];
        assert_eq!(p.decide(&c).view, View::Real);
    }

    #[test]
    fn install_argv_shapes() {
        let yes: &[&[&str]] = &[
            &["npm", "install"],
            &["npm", "ci"],
            &["/usr/bin/node", "/usr/lib/node_modules/npm/bin/npm-cli.js", "i"],
            &["pnpm", "add", "left-pad"],
            &["yarn"],
            &["yarn", "--frozen-lockfile"],
            &["npx", "cowsay"],
            &["pip", "install", "requests"],
            &["python3", "-m", "pip", "install", "x"],
            &["uv", "pip", "install", "x"],
            &["uv", "sync"],
        ];
        let no: &[&[&str]] = &[
            &["npm", "run", "dev"],
            &["yarn", "start"],
            &["pip", "list"],
            &["node", "server.js"],
            &["uv", "run", "app.py"],
        ];
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for a in yes {
            assert!(argv_is_install(&v(a)), "{a:?}");
        }
        for a in no {
            assert!(!argv_is_install(&v(a)), "{a:?}");
        }
    }

    #[test]
    fn cargo_build_script_and_rustc() {
        let p = Policy::parse("[[rule]]\nview = \"real\"\nexe = \"/home/u/**\"\n").unwrap();
        let bs = proc(
            10,
            "/home/u/proj/target/debug/build/foo-1234/build-script-build",
            &["build-script-build"],
            CG,
        );
        assert_eq!(p.decide(&caller(bs, vec![])).rule, "builtin:package-install");
        let rustc = proc(10, "/home/u/.rustup/toolchains/x/bin/rustc", &["rustc"], CG);
        assert_eq!(
            p.decide(&caller(rustc, vec![])).rule,
            "builtin:package-install"
        );
        let app = proc(10, "/home/u/proj/target/debug/app", &["app"], CG);
        assert_eq!(p.decide(&caller(app, vec![])).view, View::Real);
    }

    #[test]
    fn agents_are_redacted_and_builtin_can_be_disabled() {
        let pol = r#"
            [defaults]
            disable_builtin = ["ai-agent"]
            [[rule]]
            view = "real"
            exe = "/usr/bin/cat"
        "#;
        let allow_cat = Policy::parse("[[rule]]\nview = \"real\"\nexe = \"/usr/bin/cat\"\n").unwrap();
        let agent = proc(9, "/home/u/.local/bin/claude", &["claude"], CG);
        let cat = proc(10, "/usr/bin/cat", &["cat", ".env"], CG);
        let c = caller(cat, vec![agent]);
        assert_eq!(allow_cat.decide(&c).rule, "builtin:ai-agent");
        assert_eq!(Policy::parse(pol).unwrap().decide(&c).view, View::Real);

        let mut c = caller(proc(10, "/usr/bin/cat", &["cat"], CG), vec![]);
        c.env_hints = vec!["CLAUDECODE=1".into()];
        assert_eq!(allow_cat.decide(&c).rule, "builtin:ai-agent");
    }

    #[test]
    fn user_movable_cgroup_cannot_grant_real_alone() {
        let pol = "[[rule]]\nview = \"real\"\ncgroup = \"/user.slice/*\"\n";
        let p = Policy::parse(pol).unwrap();
        let mut c = caller(proc(10, "/usr/bin/cat", &["cat"], CG), vec![]);
        assert_eq!(p.decide(&c).view, View::Real);
        c.cgroup_user_movable = true;
        assert_eq!(p.decide(&c).view, View::Redacted);
        // Paired with exe it's a narrowing, which is fine.
        let pol = "[[rule]]\nview = \"real\"\nexe = \"/usr/bin/cat\"\ncgroup = \"/user.slice/*\"\n";
        assert_eq!(Policy::parse(pol).unwrap().decide(&c).view, View::Real);
    }

    #[test]
    fn builtin_does_not_loosen_canary() {
        let p = Policy::parse("[[rule]]\nview = \"canary\"\ncmdline = \"npm*\"\n").unwrap();
        let c = caller(proc(10, "/usr/bin/node", &["npm", "install"], CG), vec![]);
        assert_eq!(p.decide(&c).view, View::Canary);
    }

    #[test]
    fn session_root_needs_verification() {
        let p = Policy::parse("[[rule]]\nview = \"real\"\nsession_root = \"tmux\"\n").unwrap();
        let mut c = caller(proc(10, "/usr/bin/cat", &["cat"], CG), vec![]);
        c.session_root = Some(SessionRoot {
            kind: SessionKind::Tmux,
            pid: 5,
            verified: false,
        });
        assert_eq!(p.decide(&c).view, View::Redacted);
        c.session_root.as_mut().unwrap().verified = true;
        assert_eq!(p.decide(&c).view, View::Real);
    }

    #[test]
    fn stricter_view_ordering() {
        assert!(View::Real < View::Redacted && View::Redacted < View::Canary);
        assert_eq!(View::Real.max(View::Canary), View::Canary);
    }
}
