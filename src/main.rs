use std::iter::zip;

const CHARLIE_STRING: &[u8; 32] = b"Charlie is the designer of P2P!!";
const CHARLIE_CHUNKS: [u32; 8] = {
    let mut res: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut i = 0;

    while i < res.len() {
        res[i] = u32::from_le_bytes([
            CHARLIE_STRING[std::mem::size_of::<u32>() * i],
            CHARLIE_STRING[std::mem::size_of::<u32>() * i + 1],
            CHARLIE_STRING[std::mem::size_of::<u32>() * i + 2],
            CHARLIE_STRING[std::mem::size_of::<u32>() * i + 3],
        ]);
        i += 1;
    }

    res
};

fn charlie_cypher(buffer: &mut [u8]) {
    let mut iter = buffer.chunks_exact_mut(std::mem::size_of::<u32>() * 4);

    for chunk in &mut iter {
        let (slice0, rest) = chunk.split_at_mut(std::mem::size_of::<u32>());
        let (slice1, rest) = rest.split_at_mut(std::mem::size_of::<u32>());
        let (slice2, rest) = rest.split_at_mut(std::mem::size_of::<u32>());
        let (slice3, _) = rest.split_at_mut(std::mem::size_of::<u32>());

        let chunk0 = u32::from_le_bytes(slice0.try_into().unwrap());
        let chunk1 = u32::from_le_bytes(slice1.try_into().unwrap());
        let chunk2 = u32::from_le_bytes(slice2.try_into().unwrap());
        let chunk3 = u32::from_le_bytes(slice3.try_into().unwrap());

        let chunk0 = chunk0.rotate_right(1) ^ CHARLIE_CHUNKS[0];
        let chunk1 = chunk1.rotate_right(5) ^ CHARLIE_CHUNKS[1];
        let chunk2 = chunk2.rotate_right(9) ^ CHARLIE_CHUNKS[2];
        let chunk3 = chunk3.rotate_right(13) ^ CHARLIE_CHUNKS[3];

        let new_chunk0 = (chunk2 & 0xff00) 
            | ((chunk2 & 0xff) << 16) 
            | (chunk2 >> 24) 
            | (chunk3 & 0xff000000);
        let new_chunk1 = (chunk2 >> 8 & 0xff00)
            | ((chunk3 & 0xff) << 0x10)
            | (chunk3 >> 8)
            | ((chunk3 & 0xff0000) << 8);
        let new_chunk2 = (chunk0 << 0x18)
            | (chunk0 & 0xff00)
            | ((chunk1 << 8) & 0xff0000)
            | (chunk0 >> 0x10 & 0xff);
        let new_chunk3 = (chunk0 & 0xff000000)
            | (chunk1 >> 8 & 0xff0000)
            | (chunk1 >> 0x10 & 0xff)
            | (chunk1 << 0x8 & 0xff00);

        let new_chunk0 = new_chunk0.rotate_right(3);
        let new_chunk1 = new_chunk1.rotate_right(7);
        let new_chunk2 = new_chunk2.rotate_right(11);
        let new_chunk3 = new_chunk3.rotate_right(15);

        slice0.copy_from_slice(&u32::to_le_bytes(new_chunk0));
        slice1.copy_from_slice(&u32::to_le_bytes(new_chunk1));
        slice2.copy_from_slice(&u32::to_le_bytes(new_chunk2));
        slice3.copy_from_slice(&u32::to_le_bytes(new_chunk3));
    }

    let remainder = iter.into_remainder();

    for (r, s) in zip(&mut *remainder, CHARLIE_STRING) {
        *r ^= s
    }

    if remainder.len() == 8 {
        let reordered_bytes = [
            remainder[7],
            remainder[4],
            remainder[3],
            remainder[2],
            remainder[1],
            remainder[6],
            remainder[5],
            remainder[0],
        ];
        remainder.copy_from_slice(&reordered_bytes);
    } else if remainder.len() == 4 {
        let reordered_bytes = [remainder[2], remainder[3], remainder[0], remainder[1]];
        remainder.copy_from_slice(&reordered_bytes);
    } else if remainder.len() == 2 {
        let reordered_bytes = [remainder[1], remainder[2]];
        remainder.copy_from_slice(&reordered_bytes);
    }
}

fn charlie_decypher(buffer: &mut [u8]) {
    let mut iter = buffer.chunks_exact_mut(std::mem::size_of::<u32>() * 4);

    for chunk in &mut iter {
        let (slice0, rest) = chunk.split_at_mut(std::mem::size_of::<u32>());
        let (slice1, rest) = rest.split_at_mut(std::mem::size_of::<u32>());
        let (slice2, rest) = rest.split_at_mut(std::mem::size_of::<u32>());
        let (slice3, _) = rest.split_at_mut(std::mem::size_of::<u32>());

        let chunk0 = u32::from_le_bytes(slice0.try_into().unwrap());
        let chunk1 = u32::from_le_bytes(slice1.try_into().unwrap());
        let chunk2 = u32::from_le_bytes(slice2.try_into().unwrap());
        let chunk3 = u32::from_le_bytes(slice3.try_into().unwrap());

        let new_chunk0 = chunk0.rotate_left(3);
        let new_chunk1 = chunk1.rotate_left(7);
        let new_chunk2 = chunk2.rotate_left(11);
        let new_chunk3 = chunk3.rotate_left(15);

        let chunk2 = ((new_chunk0 & 0xff00) >> 8)
            | ((new_chunk0 & 0xff0000) >> 16)
            | ((new_chunk0 & 0xff) << 24)
            | (new_chunk0 & 0xff000000);
        let chunk3 = ((new_chunk1 & 0xff00) << 8)
            | ((new_chunk1 & 0xff0000) << 8)
            | ((new_chunk1 & 0xff) << 8)
            | (new_chunk1 >> 8);
        let chunk0 = (new_chunk2 >> 0x18)
            | (new_chunk2 & 0xff00)
            | ((new_chunk2 >> 8) & 0xff0000)
            | ((new_chunk2 & 0xff) << 0x10);
        let chunk1 = (new_chunk3 >> 0x18)
            | ((new_chunk3 >> 8) & 0xff00)
            | ((new_chunk3 & 0xff) << 8)
            | ((new_chunk3 & 0xff0000) >> 8);

        let chunk0 = chunk0 ^ CHARLIE_CHUNKS[0];
        let chunk1 = chunk1 ^ CHARLIE_CHUNKS[1];
        let chunk2 = chunk2 ^ CHARLIE_CHUNKS[2];
        let chunk3 = chunk3 ^ CHARLIE_CHUNKS[3];

        let chunk0 = chunk0.rotate_left(1);
        let chunk1 = chunk1.rotate_left(5);
        let chunk2 = chunk2.rotate_left(9);
        let chunk3 = chunk3.rotate_left(13);

        slice0.copy_from_slice(&u32::to_le_bytes(chunk0));
        slice1.copy_from_slice(&u32::to_le_bytes(chunk1));
        slice2.copy_from_slice(&u32::to_le_bytes(chunk2));
        slice3.copy_from_slice(&u32::to_le_bytes(chunk3));
    }

    let remainder = iter.into_remainder();

    if remainder.len() == 8 {
        let reordered_bytes = [
            remainder[7],
            remainder[6],
            remainder[3],
            remainder[4],
            remainder[5],
            remainder[2],
            remainder[1],
            remainder[0],
        ];
        remainder.copy_from_slice(&reordered_bytes);
    } else if remainder.len() == 4 {
        let reordered_bytes = [remainder[2], remainder[3], remainder[0], remainder[1]];
        remainder.copy_from_slice(&reordered_bytes);
    } else if remainder.len() == 2 {
        let reordered_bytes = [remainder[1], remainder[0]];
        remainder.copy_from_slice(&reordered_bytes);
    }

    for (r, s) in zip(&mut *remainder, CHARLIE_STRING) {
        *r ^= s
    }
}

fn main() {
    println!("Hello, world!");
}
