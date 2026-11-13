//! No dependencies or shell. Only the fixed production profile is executable.
use std::{env, fs, process::Command, os::unix::process::CommandExt};

fn required_file(name: &str) -> String {
    let path = format!("/run/secrets/{name}");
    let value = fs::read_to_string(&path).unwrap_or_else(|_| fail(&format!("missing or unreadable {path}")));
    if value.trim().is_empty() { fail(&format!("empty {path}")); }
    value.trim_end().to_string()
}
fn fail(message: &str) -> ! {
    eprintln!("rauthy-ubi: {message}");
    std::process::exit(1)
}
fn main() {
    if env::args().len() != 1 { fail("command overrides are unsupported"); }
    let mut command = Command::new("/usr/local/bin/rauthy");
    command.env_clear().args(["serve", "-c", "/etc/rauthy/production.toml"]);
    for name in ["server.crt", "server.key", "ca.crt"] { required_file(name); }
    for (name, key) in [
        ("pg-password", "PG_PASSWORD"), ("pg-ca.crt", "PG_TLS_ROOT_CA"),
        ("encryption-keys", "ENC_KEYS"), ("encryption-key-active", "ENC_KEY_ACTIVE"),
        ("raft-secret", "HQL_SECRET_RAFT"), ("api-secret", "HQL_SECRET_API"),
        ("admin-password-argon2id", "BOOTSTRAP_ADMIN_PASSWORD_ARGON2ID"),
    ] { command.env(key, required_file(name)); }
    for key in ["PUB_URL", "PG_HOST", "PG_USER", "PG_DB_NAME", "RP_ID", "RP_ORIGIN", "BOOTSTRAP_ADMIN_EMAIL"] {
        let value = env::var(key).unwrap_or_else(|_| fail(&format!("missing {key}")));
        if value.is_empty() { fail(&format!("empty {key}")); }
        command.env(key, value);
    }
    command.env("PG_PORT", env::var("PG_PORT").unwrap_or_else(|_| "5432".into()));
    command.env("SSL_CERT_FILE", "/run/secrets/ca.crt");
    command.env("HTTP_CUST_ROOT_CA_BUNDLE", required_file("ca.crt"));
    command.env("HOME", "/data").env("LANG", "C.UTF-8").env("TZ", "UTC");
    // Never inherit upstream configuration overrides, test mode, proxy, or TLS bypasses.
    let error = command.exec();
    fail(&format!("exec failed: {error}"));
}
