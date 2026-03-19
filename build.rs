//=-- Investi-Gator Build Script
//=-- Compiles Windows resources including the alligator icon

fn main() {
    //=-- Compile Windows resource file (only on Windows)
    #[cfg(windows)]
    {
        let _ = embed_resource::compile("resources/investi-gator.rc", embed_resource::NONE);
    }
}
