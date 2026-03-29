// Build script: enable WinFsp delayload linking so the binary can run even
// when the WinFsp DLL is not installed. See winfsp crate docs.
fn main() {
    winfsp::build::winfsp_link_delayload();
}
