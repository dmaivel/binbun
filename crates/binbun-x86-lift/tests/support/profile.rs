//! A processor profile (`crates/binbun-x86-lift/profiles/*.toml`): per
//! site, the rule a processor follows where L0 leaves a value undefined,
//! `unknown` or `varies`.
//! Read here for the tests that measure and check profiles.

use binbun_semantics::interpret::Value;
use binbun_semantics::ir::SiteId;
use binbun_semantics::rule::Rule;
use binbun_x86_lift::X86;

/// What a profile says about one site.
#[derive(Clone, Debug)]
pub enum Choice {
    /// The processor computes this.
    Rule(Rule),
    /// No rule of the library fits.
    Unknown,
    /// The same input gave two answers.
    Varies,
}

/// A profile, its rules indexed by [`SiteId`].
#[derive(Clone, Debug)]
pub struct Profile {
    /// `intel-raptor-cove`.
    pub id: String,
    /// The CPUs of its first measurement (`0-15`).
    pub cpus: String,
    /// Per site, if the file has it.
    pub choices: Vec<Option<Choice>>,
}

/// The site table as profiles name it: each site's name and inputs, in
/// order, hashed (`blake3:...`): a profile measured against another table
/// is refused.
pub fn site_table_hash() -> String {
    let mut hasher = blake3::Hasher::new();
    for site in X86.sites {
        hasher.update(site.name.as_bytes());
        for input in site.inputs {
            hasher.update(b",");
            hasher.update(input.as_bytes());
        }
        hasher.update(b";");
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

impl Profile {
    /// Reads a profile's text.
    ///
    /// # Errors
    ///
    /// Not a profile of format 1 for this site table, a site that does not
    /// exist, or a rule that does not read.
    pub fn parse(text: &str) -> Result<Self, String> {
        let table: toml::Table = toml::from_str(text).map_err(|error| error.to_string())?;
        let string = |key: &str| {
            table
                .get(key)
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("no `{key}`"))
        };
        if table.get("format").and_then(toml::Value::as_integer) != Some(1) {
            return Err("not format 1".to_owned());
        }
        let hash = site_table_hash();
        if string("sites")? != hash {
            return Err(format!(
                "measured against another site table ({}, now {hash})",
                string("sites")?
            ));
        }
        let cpus = table
            .get("measured")
            .and_then(toml::Value::as_array)
            .and_then(|list| list.first())
            .and_then(|first| first.get("cpus"))
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut choices = vec![None; X86.sites.len()];
        let sites = table
            .get("site")
            .and_then(toml::Value::as_table)
            .ok_or("no sites")?;
        for (name, entry) in sites {
            let id = X86
                .find_site(name)
                .ok_or_else(|| format!("no site {name}"))?;
            let info = X86.site(id).ok_or_else(|| format!("no site {name}"))?;
            let rule = entry
                .get("rule")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| format!("{name}: no rule"))?;
            let choice = match rule {
                "unknown" => Choice::Unknown,
                "varies" => Choice::Varies,
                text => Choice::Rule(
                    Rule::parse(text, info.inputs).map_err(|error| format!("{name}: {error}"))?,
                ),
            };
            if let Some(slot) = choices.get_mut(usize::from(id.0)) {
                *slot = Some(choice);
            }
        }
        Ok(Self {
            id: string("id")?.to_owned(),
            cpus,
            choices,
        })
    }

    /// Reads the profile at `path`.
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse), or the file cannot be read.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
        Self::parse(&text).map_err(|error| format!("{path}: {error}"))
    }

    /// The rule of `site`, if the profile has one.
    pub fn rule(&self, site: SiteId) -> Option<&Rule> {
        match self.choices.get(usize::from(site.0))? {
            Some(Choice::Rule(rule)) => Some(rule),
            Some(Choice::Unknown | Choice::Varies) | None => None,
        }
    }

    /// What the processor gives at `site` for `inputs`, `width` bits; `None`
    /// where the profile has no rule (or the rule does not fit these
    /// widths).
    pub fn value(&self, site: SiteId, inputs: &[Value], width: u16) -> Option<Value> {
        let widths: Vec<u16> = inputs.iter().map(Value::width).collect();
        let compiled = self.rule(site)?.instantiate(&widths, width).ok()?;
        compiled.eval(inputs).ok()
    }
}
