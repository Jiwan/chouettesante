pub fn hexdump(data: &[u8]) {
    const BYTES_PER_LINE: usize = 16;

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        print!("{:08x}  ", i * BYTES_PER_LINE);

        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        // Pad spacing if chunk is less than full line
        let missing = BYTES_PER_LINE - chunk.len();
        if missing > 0 {
            for _ in 0..missing {
                print!("   ");
            }
            if chunk.len() <= 8 {
                print!(" "); // align middle space
            }
        }
        
        print!(" |");
        for byte in chunk {
            let ch = *byte as char;
            if ch.is_ascii_graphic() || ch == ' ' {
                print!("{}", ch);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}