use std::env;
use std::fs;
use std::path::PathBuf;

const PE_MACHINE_AMD64: u16 = 0x8664;
const PE_MACHINE_ARM64: u16 = 0xaa64;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTLE_EMBED_WINTUN_DLL");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let generated = out_dir.join("embedded_wintun.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let contents = match env::var_os("RUSTLE_EMBED_WINTUN_DLL") {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_file() {
                panic!(
                    "RUSTLE_EMBED_WINTUN_DLL does not point to a file: {}",
                    path.display()
                );
            }
            println!("cargo:rerun-if-changed={}", path.display());
            if target_os == "windows" {
                let bytes = fs::read(&path).unwrap_or_else(|err| {
                    panic!(
                        "failed to read RUSTLE_EMBED_WINTUN_DLL {}: {err}",
                        path.display()
                    )
                });
                validate_embedded_wintun_arch(&bytes, &target_arch, &path.display().to_string());
            }
            let literal = format!("{:?}", path.display().to_string());
            format!(
                "#[cfg_attr(not(windows), allow(dead_code))]\npub(crate) static EMBEDDED_WINTUN_DLL: Option<&'static [u8]> = Some(include_bytes!({literal}));\n"
            )
        }
        None => "#[cfg_attr(not(windows), allow(dead_code))]\npub(crate) static EMBEDDED_WINTUN_DLL: Option<&'static [u8]> = None;\n".to_owned(),
    };

    fs::write(generated, contents).expect("failed to write generated embedded_wintun.rs");
}

fn validate_embedded_wintun_arch(bytes: &[u8], target_arch: &str, source: &str) {
    let expected = expected_windows_pe_machine(target_arch).unwrap_or_else(|| {
        panic!("unsupported Windows target architecture for embedded Wintun: {target_arch}")
    });
    let actual = pe_machine_from_bytes(bytes).unwrap_or_else(|err| {
        panic!("RUSTLE_EMBED_WINTUN_DLL must be a PE/COFF DLL for {target_arch}: {source}: {err}")
    });
    if actual != expected {
        panic!(
            "RUSTLE_EMBED_WINTUN_DLL architecture mismatch for target {target_arch}: expected {}, found {} in {source}",
            pe_machine_name(expected),
            pe_machine_name(actual),
        );
    }
}

fn expected_windows_pe_machine(target_arch: &str) -> Option<u16> {
    match target_arch {
        "x86_64" => Some(PE_MACHINE_AMD64),
        "aarch64" => Some(PE_MACHINE_ARM64),
        _ => None,
    }
}

fn pe_machine_from_bytes(bytes: &[u8]) -> Result<u16, &'static str> {
    if bytes.len() < 0x40 {
        return Err("file is too small for a DOS header");
    }
    if &bytes[..2] != b"MZ" {
        return Err("missing MZ DOS signature");
    }

    let pe_offset =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let machine_offset = pe_offset
        .checked_add(4)
        .ok_or("PE header offset overflowed")?;
    let machine_end = machine_offset
        .checked_add(2)
        .ok_or("PE machine offset overflowed")?;
    if bytes.len() < machine_end {
        return Err("file is too small for a PE header");
    }
    if &bytes[pe_offset..machine_offset] != b"PE\0\0" {
        return Err("missing PE signature");
    }

    Ok(u16::from_le_bytes([
        bytes[machine_offset],
        bytes[machine_offset + 1],
    ]))
}

fn pe_machine_name(machine: u16) -> String {
    match machine {
        PE_MACHINE_AMD64 => "x86_64".to_owned(),
        PE_MACHINE_ARM64 => "aarch64".to_owned(),
        other => format!("unknown PE machine 0x{other:04x}"),
    }
}
