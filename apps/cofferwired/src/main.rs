use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use cofferwired::{router, ConnectionLimit, RelayService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse()?;
    let service = RelayService::open(&arguments.database)?;
    let tls = RustlsConfig::from_pem_file(&arguments.certificate, &arguments.private_key).await?;

    eprintln!("cofferwired listening on https://{}", arguments.address);
    let acceptor = RustlsAcceptor::new(tls).acceptor(ConnectionLimit::new());
    axum_server::bind(arguments.address)
        .acceptor(acceptor)
        .serve(router(service).into_make_service())
        .await?;
    Ok(())
}

struct Arguments {
    address: SocketAddr,
    database: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl Arguments {
    fn parse() -> Result<Self, Box<dyn Error>> {
        let mut values = env::args_os().skip(1);
        let address = required(&mut values, "BIND_ADDRESS")?
            .into_string()
            .map_err(|_| "BIND_ADDRESS is not valid UTF-8")?
            .parse()?;
        let database = PathBuf::from(required(&mut values, "DATABASE_PATH")?);
        let certificate = PathBuf::from(required(&mut values, "CERTIFICATE_PEM")?);
        let private_key = PathBuf::from(required(&mut values, "PRIVATE_KEY_PEM")?);
        if values.next().is_some() {
            return Err(
                "usage: cofferwired BIND_ADDRESS DATABASE_PATH CERTIFICATE_PEM PRIVATE_KEY_PEM"
                    .into(),
            );
        }
        Ok(Self {
            address,
            database,
            certificate,
            private_key,
        })
    }
}

fn required(
    values: &mut impl Iterator<Item = OsString>,
    name: &'static str,
) -> Result<OsString, Box<dyn Error>> {
    values.next().ok_or_else(|| {
        format!(
            "missing {name}; usage: cofferwired BIND_ADDRESS DATABASE_PATH CERTIFICATE_PEM PRIVATE_KEY_PEM"
        )
        .into()
    })
}
