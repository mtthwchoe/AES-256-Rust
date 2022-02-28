mod key_expansion;
use key_expansion::key_expansion;
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;

//let inverseSubBytes = [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125];

fn main() {

	let args: Vec<String> = env::args().collect();
	if args.len() != 4 {
		println!("Invalid number of arguments\n");
		return;
	}
	
	let key_file = read_file_vec(&args[1]);
	let key = key_file.unwrap();	
	let key_sched = key_expansion(key);
	let byte_stream = read_all(&args[2]).unwrap();
	let mut key_count = 0;
	let mut buffer = Vec::new();

	let sub_bytes = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
	
	for block in 0..((byte_stream.len() / 16)) { // divide byte stream into 16 byte blocks
		let mut state = Vec::new();

		for x in 0..16 {
			state.push(byte_stream[x + block * 16]);
		}
		
		for i in 0..4 {
			let temp = &key_sched[key_count].to_be_bytes();
			for j in 0..4 {
				state[j + (i * 4)] = state[j + (i * 4)] ^ temp[j];
			}
			key_count += 1;
		}
		
		for _k in 0..13 {
			for x in 0..16 {	// substitute bytes
				state[x] = sub_bytes[state[x] as usize];
			}

			for x in 0..4 {		// shift rows
				let mut temp2 = u32::from_be_bytes([state[x],state[x+4],state[x+8],state[x+12]]);
				temp2 = temp2.rotate_left((x as u32)*8);
				let temp3 = temp2.to_be_bytes();
				state[x] = temp3[0];
				state[x+4] = temp3[1];
				state[x+8] = temp3[2];
				state[x+12] = temp3[3];
			}
								// mix columns
			let matrix = [2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2];
			let mut temp = Vec::new();
			for col in 0..4 { // matrix multiplication
				for row in 0..4 {
					temp.push(gf2n_multiply(state[col*4+0], matrix[row*4+0]) ^ gf2n_multiply(state[col*4+1], matrix[row*4+1]) ^ gf2n_multiply(state[col*4+2], matrix[row*4+2]) ^ gf2n_multiply(state[col*4+3], matrix[row*4+3]));
					//print!("{}\n", temp[row + col * 4]);
				}
			}
			state.copy_from_slice(&temp[0..]);
			temp.clear();
			
			for i in 0..4 {		// add round key
				let temp = &key_sched[key_count].to_be_bytes();
				for j in 0..4 {
					state[j + (i * 4)] = state[j + (i * 4)] ^ temp[j];
				}
				key_count += 1;
			}
			
		}
		
		for x in 0..16 {
			state[x] = sub_bytes[state[x] as usize];
		}
		
		for x in 0..4 {
			let mut temp2 = u32::from_be_bytes([state[x],state[x+4],state[x+8],state[x+12]]);
			temp2 = temp2.rotate_left((x as u32)*8);
			let temp3 = temp2.to_be_bytes();
			state[x] = temp3[0];
			state[x+4] = temp3[1];
			state[x+8] = temp3[2];
			state[x+12] = temp3[3];
		}
		
		for i in 0..4 {
			let temp = &key_sched[key_count].to_be_bytes();
			for j in 0..4 {
				state[j + (i * 4)] = state[j + (i * 4)] ^ temp[j];
			}
			key_count += 1;
		}
		
		for i in 0..16 {
			byte_to_ascii(state[i], &mut buffer);
		}
		
		key_count = 0;
		state.clear();
	}
	if write_block(&args[3], &buffer).is_ok() {
		print!("Write successful\n");
	}
	else {
		print!("Write failed\n");
	}
}

fn read_file_vec(filepath: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = fs::read(filepath)?;
    Ok(data)
}

fn read_all(filepath: &str) -> io::Result<Vec<u8>> {
	let mut f = File::open(filepath)?;
    let mut byte_stream = Vec::new();
	f.read_to_end(&mut byte_stream)?;
    //print!("{}",f.read_to_end(&mut byte_stream)?);
    Ok(byte_stream)
}

fn write_block(filepath: &str, state: &Vec<u8>) -> io::Result<usize> {
	let mut f = File::create(filepath)?;
	let written = f.write(&state)?;
	Ok(written)
}

fn gf2n_multiply( aa: u8, mut b: u8) -> u8{
	let mut a = aa as u32;
	let overflow = 0x100;
	let modulus = 0x11B;  // AES GF(2^8) representation
    let mut sum = 0;
    while b > 0 {
        if b & 1 == 1{
			sum = sum ^ a;             // if last bit of b is 1, add a to the sum
        }
		b = b >> 1;                           // divide b by 2, discarding the last bit
        a = a << 1;                           // multiply a by 2
        if (a as u32) & overflow  == overflow {
			a = (a as u32) ^ modulus;    // reduce a modulo the AES polynomial
		}
	}
	//print!("{}\n", sum);
    sum as u8
}

fn byte_to_ascii(byte: u8, buffer: &mut Vec<u8>) {
	let mut one = byte / 16;
	let mut zero = byte % 16;
	if one < 10 {
		one = one + 48;
	}
	else {
		one = one + 55;
	}
	if zero < 10 {
		zero = zero + 48;
	}
	else {
		zero = zero + 55;
	}
	buffer.push(char::from_u32(one as u32).unwrap() as u8);
	buffer.push(char::from_u32(zero as u32).unwrap() as u8);
}