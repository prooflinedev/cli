use super::*;

fn archive(name: &str, kind: tar::EntryType, content: &[u8]) -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_mode(0o755);
    header.set_size(content.len() as u64);
    if kind.is_symlink() {
        header.set_link_name("/tmp/foreign").unwrap();
    }
    header.set_cksum();
    builder.append_data(&mut header, name, content).unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn integrity_and_archive_refusals_preserve_installed_binary() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("proofline");
    fs::write(&destination, b"old binary").unwrap();
    let good = archive("proofline", tar::EntryType::Regular, b"new binary");
    let digest = format!("{:x}", Sha256::digest(&good));
    let sums = format!("{digest}  release.tar.gz\n");
    verify(&good, sums.as_bytes(), "release.tar.gz").unwrap();
    for invalid in [
        format!("{}  release.tar.gz\n", "0".repeat(64)),
        format!("{sums}{sums}"),
        format!("{digest}  other.tar.gz\n"),
    ] {
        assert!(
            verify_and_replace(&good, invalid.as_bytes(), "release.tar.gz", &destination).is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"old binary");
    }
    for bad in [
        archive("foreign", tar::EntryType::Regular, b"foreign"),
        archive("proofline", tar::EntryType::Symlink, b""),
        archive("proofline", tar::EntryType::Regular, b""),
        b"broken gzip".to_vec(),
    ] {
        assert!(replace(&bad, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"old binary");
    }
    replace(&good, &destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"new binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[test]
fn versions_cannot_inject_paths_or_notices_or_trigger_a_downgrade() {
    for invalid in [
        "1.2",
        "1.2.3/evil",
        "1.2.3\nnotice",
        "1.2.3-beta",
        "-1.2.3",
        "1..3",
        "999999999999999999999999.2.3",
    ] {
        assert!(version(invalid).is_err(), "{invalid}");
        assert!(!newer(invalid));
    }
    assert!(newer("0.10.0"));
    assert!(!newer(env!("CARGO_PKG_VERSION")));
    assert!(!newer("0.0.9"));
}

#[test]
fn installer_directory_and_bounded_cache() {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("proofline");
    fs::write(&binary, b"binary").unwrap();
    let binary = fs::canonicalize(binary).unwrap();
    assert_eq!(install_path(&binary, directory.path()).unwrap(), binary);
    assert!(install_path(&directory.path().join("cargo/proofline"), directory.path()).is_err());
    let cache = directory.path().join("cache/update.json");
    write_cache(
        &cache,
        &Cache {
            checked: now(),
            latest: Some("9.1.0".to_owned()),
        },
    )
    .unwrap();
    // A fresh cached result schedules no child, and survives the next invocation.
    prepare_check(&cache, &["--json".into()], true, || {
        anyhow::bail!("a fresh cache must not launch discovery")
    })
    .unwrap();
    assert_eq!(read_cache(&cache).unwrap().latest.as_deref(), Some("9.1.0"));
    fs::write(&cache, vec![b' '; 1025]).unwrap();
    assert!(read_cache(&cache).is_err());
}

#[tokio::test]
async fn discovery_rejects_bad_bounded_and_offline_responses() {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/valid", get(|| async { "10.2.0\n" }))
                .route("/invalid", get(|| async { "<html>" }))
                .route("/large", get(|| async { "9".repeat(129) }))
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        "10.2.0"
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    assert_eq!(
        latest_from(&http, &format!("{address}/valid"))
            .await
            .unwrap(),
        "10.2.0"
    );
    for path in ["invalid", "large", "slow", "missing"] {
        assert!(
            latest_from(&http, &format!("{address}/{path}"))
                .await
                .is_err()
        );
    }
    // Production clients refuse HTTP before a release request can leave the process.
    assert!(
        latest_from(
            &client(Duration::from_secs(1)).unwrap(),
            &format!("{address}/valid")
        )
        .await
        .is_err()
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(
        latest_from(&http, &format!("{address}/valid"))
            .await
            .is_err()
    );
}

#[test]
fn notices_are_suppressed_for_machine_and_hook_commands() {
    let cache = Cache {
        checked: now(),
        latest: Some("9.0.0".to_owned()),
    };
    for args in [
        vec!["hook", "run", "pre-commit"],
        vec!["hooks", "install"],
        vec!["hooks", "uninstall"],
        vec!["review", "--json"],
        vec!["review", "--schema"],
        vec!["findings", "--sarif"],
        vec!["mcp"],
        vec!["ci", "review"],
    ] {
        let args: Vec<_> = args.into_iter().map(std::ffi::OsString::from).collect();
        assert!(suggestion(&cache, &args, true).is_none());
    }
    assert!(suggestion(&cache, &["status".into()], false).is_none());
    assert!(suggestion(&cache, &["status".into()], true).is_some());
}

// This same test executable supplies a real child fixture. All endpoint and
// fixture-mode injection lives in cfg(test), never in the customer binary.
#[tokio::test]
async fn detached_discovery_is_serialized_and_notices_arrive_on_the_next_invocation() {
    use axum::{Router, routing::get};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    const MODE: &str = "PROOFLINE_DISCOVERY_FIXTURE_MODE";
    const CACHE: &str = "PROOFLINE_DISCOVERY_FIXTURE_CACHE";
    const ADDRESS: &str = "PROOFLINE_DISCOVERY_FIXTURE_ADDRESS";
    const TEST: &str =
        "update::tests::detached_discovery_is_serialized_and_notices_arrive_on_the_next_invocation";
    if let Ok(mode) = std::env::var(MODE) {
        let path = PathBuf::from(std::env::var_os(CACHE).unwrap());
        let address = std::env::var(ADDRESS).unwrap();
        if mode == "worker" {
            assert!(std::env::var_os("PROOFLINE_TOKEN").is_none());
            assert!(std::env::var_os("AWS_SECRET_ACCESS_KEY").is_none());
            let http = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();
            refresh(&http, &address, path).await.unwrap();
        } else {
            assert_eq!(mode, "invocation");
            let mut worker = checker_command(&std::env::current_exe().unwrap());
            worker
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, "worker")
                .env(CACHE, &path)
                .env(ADDRESS, address);
            let notice = tokio::task::spawn_blocking(move || {
                prepare_check(&path, &["status".into()], true, || spawn_check(worker))
            })
            .await
            .unwrap()
            .unwrap();
            if let Some(notice) = notice {
                println!("{notice}");
            }
        }
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("update.json");
    let received = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let request_count = Arc::clone(&received);
    let response_gate = Arc::clone(&release);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}/latest", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/latest",
                get(move || {
                    let count = Arc::clone(&request_count);
                    let gate = Arc::clone(&response_gate);
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        gate.notified().await;
                        "9.0.0\n"
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let invoke = || {
        let mut command = checker_command(&std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST, "--nocapture"])
            .env(MODE, "invocation")
            .env(CACHE, &cache)
            .env(ADDRESS, &address)
            .env("PROOFLINE_TOKEN", "must-not-reach-worker")
            .env("AWS_SECRET_ACCESS_KEY", "must-not-reach-worker");
        tokio::process::Command::from(command)
    };
    let mut invocations = Vec::new();
    for _ in 0..4 {
        let mut command = invoke();
        invocations.push(tokio::spawn(async move { command.output().await.unwrap() }));
    }
    // Every originating invocation must exit while its real discovery child is
    // still waiting for a response. Inherited output pipes would fail this too.
    for invocation in invocations {
        let output = tokio::time::timeout(Duration::from_secs(5), invocation)
            .await
            .unwrap()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("run 'proofline update'")
        );
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while received.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(received.load(Ordering::SeqCst), 1);
    assert!(read_cache(&cache).unwrap().latest.is_none());
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if read_cache(&cache).is_ok_and(|value| value.latest.as_deref() == Some("9.0.0")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let output = invoke().output().await.unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("run 'proofline update'")
    );
    assert_eq!(received.load(Ordering::SeqCst), 1);
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}
