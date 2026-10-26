#[path = "../../harness.rs"]
mod harness;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() >= 3, "Usage: replay seeds DIRECTORY | replay TARGET INPUT");
    if args[1] == "seeds" {
        for target in harness::TARGETS {
            let dir=std::path::Path::new(&args[2]).join(target);
            std::fs::create_dir_all(&dir).unwrap();
            for (i,seed) in harness::seeds(target).iter().enumerate() {
                harness::exercise(target,seed);
                std::fs::write(dir.join(format!("seed-{i:03}")),seed).unwrap();
            }
            println!("PASS seed replay {target}");
        }
    } else {
        assert!(harness::TARGETS.contains(&args[1].as_str()));
        let bytes=std::fs::read(&args[2]).unwrap();
        assert!(bytes.len() <= harness::MAX_INPUT);
        harness::exercise(&args[1],&bytes);
        println!("PASS replay {}",args[1]);
    }
}
