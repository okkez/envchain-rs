use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use secret_service::blocking::SecretService;
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
        output: String,
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

        match &self.command {
            Some(Commands::Set { .. }) => {
                println!("Set passwords for keys.");
                self.set_password_to_env_keys(&ss)?;
            }
            Some(Commands::Run { .. }) => {
                self.run_command(&ss)?;
            }
            Some(Commands::List {}) => {
                self.list_namespace(&ss)?;
            }
            Some(Commands::Export { .. }) => {
                self.export_secrets(&ss)?;
            }
            Some(Commands::Import { .. }) => {
                self.import_secrets(&ss)?;
            }
            None => {
                self.run_command(&ss)?;
            }
        }
        Ok(())
    }

    fn set_password_to_env_keys(&self, ss: &SecretService<'a>) -> Result<(), Box<dyn Error>> {
        if let Some(Commands::Set {
            namespace,
            env_keys,
        }) = &self.command
        {
            let collection = ss.get_default_collection()?;
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
        }
        Ok(())
    }

    fn run_command(&self, ss: &SecretService<'a>) -> Result<(), Box<dyn Error>> {
        let collection = ss.get_default_collection()?;
        let properties = HashMap::from([
            ("name", self.get_namespace()),
            ("xdg:schema", "envchain.EnvironmentVariable"),
        ]);
        let items = collection.search_items(properties)?;
        let envs: HashMap<String, String> = items
            .iter()
            .map(|item| {
                let attributes = item.get_attributes().unwrap();
                let name = attributes.get("key").unwrap().to_string();
                let secret = String::from_utf8(item.get_secret().unwrap()).unwrap();
                (name, secret)
            })
            .collect();
        let (exe, args) = if let Some(Commands::Run { command, .. }) = &self.command {
            command.split_at(1)
        } else {
            self.args.split_at(1)
        };
        Command::new(exe[0].clone()).args(args).envs(envs).exec();
        Ok(())
    }

    fn get_namespace(&self) -> &str {
        if let Some(Commands::Run { namespace, .. }) = &self.command {
            namespace.as_str()
        } else {
            if let Some(namespace) = &self.namespace {
                namespace.as_str()
            } else {
                eprintln!("Failed to get namespace");
                "none"
            }
        }
    }

    fn list_namespace(&self, ss: &SecretService<'a>) -> Result<(), Box<dyn Error>> {
        let collection = ss.get_default_collection()?;
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

    fn export_secrets(&self, ss: &SecretService<'a>) -> Result<(), Box<dyn Error>> {
        let collection = ss.get_default_collection()?;
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
        if let Some(Commands::Export { output, .. }) = &self.command {
            let mut io = File::create(output)?;
            write!(io, "{}", toml)?;
        } else {
            println!("{}", toml);
        }
        Ok(())
    }

    fn import_secrets(&self, ss: &SecretService<'a>) -> Result<(), Box<dyn Error>> {
        let collection = ss.get_default_collection()?;
        if let Some(Commands::Import { input, .. }) = &self.command {
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
        }
        Ok(())
    }
}
