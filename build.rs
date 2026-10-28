//! Renders `assets/logo.svg` into RGBA bitmaps embedded by the program (so the SVG renderer
//! is not needed at run time). On Windows targets it also builds an .ico and embeds it with a
//! manifest requesting administrator rights (needed to open the SeLow/Neo drivers).

use std::path::PathBuf;

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"#;

fn render(svg: &[u8], size: u32) -> resvg::tiny_skia::Pixmap {
    use resvg::{tiny_skia, usvg};
    let tree = usvg::Tree::from_data(svg, &usvg::Options::default()).expect("valid logo.svg");
    let mut pixmap = tiny_skia::Pixmap::new(size, size).unwrap();
    let scale = size as f32 / tree.size().width();
    resvg::render(&tree, tiny_skia::Transform::from_scale(scale, scale), &mut pixmap.as_mut());
    pixmap
}

fn render_png(svg: &[u8], size: u32) -> Vec<u8> {
    render(svg, size).encode_png().expect("PNG encoding")
}

/// Straight (non-premultiplied) RGBA, as egui's IconData and the tray icons expect.
fn render_rgba(svg: &[u8], size: u32) -> Vec<u8> {
    render(svg, size)
        .pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

/// ICO container with PNG-compressed entries (supported since Windows Vista).
fn build_ico(svg: &[u8]) -> Vec<u8> {
    let sizes = [16u32, 24, 32, 48, 64, 128, 256];
    let images: Vec<Vec<u8>> = sizes.iter().map(|&s| render_png(svg, s)).collect();
    let mut ico = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0]);
    ico.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (s, img) in sizes.iter().zip(&images) {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        ico.extend_from_slice(&[dim, dim, 0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes()); // planes
        ico.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
        ico.extend_from_slice(&(img.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in &images {
        ico.extend_from_slice(img);
    }
    ico
}

fn main() {
    println!("cargo:rerun-if-changed=assets/logo.svg");
    println!("cargo:rerun-if-changed=build.rs");
    let svg = std::fs::read("assets/logo.svg").expect("assets/logo.svg");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // Pre-rendered logo bitmaps embedded by src/logo.rs (window icon, header, tray).
    for size in [256u32, 128, 64] {
        std::fs::write(out_dir.join(format!("logo{size}.rgba")), render_rgba(&svg, size)).expect("write logo");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = out_dir.join("easyether.ico");
    std::fs::write(&out, build_ico(&svg)).expect("write icon");

    let mut res = winresource::WindowsResource::new();
    res.set_icon(out.to_str().unwrap());
    res.set_manifest(MANIFEST);
    res.set("ProductName", "EasyEther");
    res.set("FileDescription", "EasyEther - peer-to-peer Ethernet sharing");
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed Windows resources: {e}");
    }
}
