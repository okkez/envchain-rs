use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use secret_service::blocking::{SecretService, Collection};
use secret_service::EncryptionType;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{collections::HashMap, error::Error};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    // #[arg(short, long)]
    // target: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
    /// Execute commands with variables defined in the specified namespace
    namespace: Option<String>,
    /// Commands to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Save values into the specified namespace
    Set {
        /// The namespace of variables
        namespace: String,
        /// Variable name list separated by comma
        #[arg(trailing_var_arg = true)]
        env_keys: Vec<String>,
    },
    /// Execute commands with defined variables
    Run {
        /// The namespace of variables
        namespace: String,
        /// Commands to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    List {},
    /// Export secrets added by envchain to the file
    Export {
        /// The output file name
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import secrets from a file
    Import {
        /// The input file name
        #[arg(short, long)]
        input: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct Entries {
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    name: String,
    key: String,
    value: String,
}

fn main() {
    let cli = Cli::parse();
    cli.execute().unwrap();
}

impl<'a> Cli {
    fn execute(&self) -> Result<(), Box<dyn Error>> {
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let collection = ss.get_default_collection()?;

        match &self.command {
            Some(Commands::Set { namespace, env_keys }) => {
                println!("Set passwords for keys.");
                self.set_password_to_env_keys(&collection, namespace, env_keys)?;
            }
            Some(Commands::Run { namespace, command }) => {
                self.run_command(&collection, namespace, command)?;
            }
            Some(Commands::List {}) => {
                self.list_namespace(&collection)?;
            }
            Some(Commands::Export { output }) => {
                self.export_secrets(&collection, output)?;
            }
            Some(Commands::Import { input }) => {
                self.import_secrets(&collection, input)?;
            }
            None => {
                if let Some(namespace) = &self.namespace {
                    self.run_command(&collection, namespace, &self.args)?;
                } else {
                    eprintln!("Failed to get namespace");
                }
            }
        }
        Ok(())
    }

    fn set_password_to_env_keys(&self, collection: &Collection<'a>, namespace: &String, env_keys: &Vec<String>) -> Result<(), Box<dyn Error>> {
        env_keys.iter().for_each(|env_key| {
            if let Ok(password) = prompt_password(format!("{}: ", env_key)) {
                let properties = HashMap::from([
                    ("key", env_key.as_str()),
                    ("name", namespace.as_str()),
                    ("xdg:schema", "envchain.EnvironmentVariable"),
                ]);
                let _ = collection.create_item(
                    format!("{}.{}", namespace, env_key).as_str(),
                    properties,
                    password.as_bytes(),
                    true,
                    "text/plain",
                );
            } else {
                eprintln!("Failed to read password for {}", env_key);
            }
        });
        Ok(())
    }

    fn run_command(&self, collection: &Collection<'a>, namespace: &String, command: &Vec<String >) -> Result<(), Box<dyn Error>> {
        let properties = HashMap::from([
            ("name", namespace.as_str()),
            ("xdg:schema", "envchain.EnvironmentVariable"),
        ]);
        let items = collection.search_items(properties)?;
        let envs: HashMap<String, String> = items
            .iter()
            .map(|item| {
                let attributes = item.get_attributes().unwrap();
                let name = attributes.get("key").unwrap().to_string();
                item.ensure_unlocked().unwrap();
                let secret = String::from_utf8(item.get_secret().unwrap()).unwrap();
                (name, secret)
            })
            .collect();
        let (exe, args) = command.split_at(1);
        Command::new(exe[0].clone()).args(args).envs(envs).exec();
        Ok(())
    }

    fn list_namespace(&self, collection: &Collection<'a>) -> Result<(), Box<dyn Error>> {
        let properties = HashMap::from([("xdg:schema", "envchain.EnvironmentVariable")]);
        let items = collection.search_items(properties)?;
        let mut namespaces: Vec<String> = items
            .iter()
            .map(|item| {
                let attributes = item.get_attributes().unwrap();
                attributes.get("name").unwrap().to_string()
            })
            .collect();
        namespaces.sort();
        namespaces.dedup();
        namespaces
            .iter()
            .for_each(|namespace| println!("{}", namespace));

        Ok(())
    }

    fn export_secrets(&self, collection: &Collection<'a>, output: &Option<String>) -> Result<(), Box<dyn Error>> {
        let properties = HashMap::from([("xdg:schema", "envchain.EnvironmentVariable")]);
        let items = collection.search_items(properties)?;
        let entries = Entries {
            entries: items
                .iter()
                .map(|item| {
                    let attributes = item.get_attributes().unwrap();
                    Entry {
                        name: attributes.get("name").unwrap().to_string(),
                        key: attributes.get("key").unwrap().to_string(),
                        value: String::from_utf8(item.get_secret().unwrap()).unwrap(),
                    }
                })
                .collect(),
        };
        let toml = toml::to_string(&entries).unwrap();
        if let Some(path) = output {
            let mut io = File::create(path)?;
            write!(io, "{}", toml)?;
        } else {
            println!("{}", toml);
        }
        Ok(())
    }

    fn import_secrets(&self, collection: &Collection<'a>, input: &String) -> Result<(), Box<dyn Error>> {
        let mut io = File::open(input)?;
        let mut toml = String::new();
        io.read_to_string(&mut toml)?;
        let entries: Result<Entries, toml::de::Error> = toml::from_str(toml.as_str());
        match entries {
            Ok(es) => es.entries.iter().for_each(|entry| {
                let properties = HashMap::from([
                    ("key", entry.key.as_str()),
                    ("name", entry.name.as_str()),
                    ("xdg:schema", "envchain.EnvironmentVariable"),
                ]);
                let _ = collection.create_item(
                    format!("{}.{}", entry.name, entry.key).as_str(),
                    properties,
                    entry.value.as_bytes(),
                    true,
                    "text/plain",
                );
            }),
            Err(e) => eprintln!("{}", e),
        }
        Ok(())
    }
}
