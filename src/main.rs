use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
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
    namespace: Option<String>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Set {
        namespace: String,
        #[arg(trailing_var_arg = true)]
        env_keys: Vec<String>,
    },
    Run {
        namespace: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
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
}
