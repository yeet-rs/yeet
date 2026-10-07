use color_eyre::Result;
use merkle_hash::MerkleTree;
use std::{
    collections::HashMap,
    fs::{self, File, read_to_string},
    io::Write,
    path::PathBuf,
};
use tracing::instrument;

use serde::{Deserialize, Serialize};
use serde_json_any_key::*;

use crate::nix;

// hash(disko+systems)
// lanzaboote-luks.nix + config.system.build.diskoScript -> /nix/store/...
// simple.nix + config.system.build.diskoScript -> /nix/store/...

#[derive(Debug, Deserialize, Serialize)]
pub struct Cache {
    /// Location of the cache
    file: PathBuf,
    /// Directories that got included in the hash
    components: Vec<String>,
    /// Resulting hash if all component directories get recursively traversed and the file contents hashed
    hash: String,
    /// (evaluated modules, evaluated attribute) -> eval result
    #[serde(with = "any_key_map")]
    evals: HashMap<(Vec<String>, String), PathBuf>,
}

impl Drop for Cache {
    fn drop(&mut self) {
        File::create(&self.file)
            .unwrap()
            .write_all(toml::to_string_pretty(self).unwrap().as_bytes())
            .unwrap();
    }
}

impl Cache {
    /// creates a new cache by feeding the required components and calculating the hash of all files
    #[instrument(err, ret)]
    pub fn from_file(components: Vec<String>, file: PathBuf) -> Result<Self> {
        let mut cache = if fs::exists(&file)? {
            let mut cache: Self = toml::from_str(&read_to_string(&file)?)?;
            cache.components = components;
            cache.file = file;
            cache
        } else {
            Self {
                file,
                components,
                hash: "".to_owned(),
                evals: HashMap::default(),
            }
        };
        cache.refresh()?;
        Ok(cache)
    }

    /// recalculate the hash of the components
    #[instrument(err)]
    pub fn refresh(&mut self) -> Result<()> {
        let mut hasher = blake3::Hasher::new();
        for component in &self.components {
            let merkle_tree = MerkleTree::builder(component).build()?;
            hasher.update(&merkle_tree.root.item.hash);
        }
        let hash = hasher.finalize().to_string();
        if hash != self.hash {
            // hash changed -> clear evals
            self.evals = HashMap::default();
            self.hash = hash;
        }
        Ok(())
    }

    /// Build a nix attr through the cache.
    /// Make sure you run `refresh` beforehand!
    #[instrument(err, ret)]
    pub fn nix_build(&mut self, modules: &[String], attr: &str) -> Result<PathBuf> {
        let cache = self.evals.get(&(modules.to_owned(), attr.to_owned()));
        match cache {
            Some(cache_hit) => Ok(cache_hit.clone()),
            None => {
                let result = nix::build(&modules, &attr)?;
                self.evals
                    .insert((modules.to_owned(), attr.to_owned()), result.clone());
                Ok(result)
            }
        }
    }
}
