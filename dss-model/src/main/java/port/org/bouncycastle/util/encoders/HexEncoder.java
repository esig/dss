package port.org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A streaming Hex encoder.
 */
public class HexEncoder implements Encoder {

	protected final byte[] encodingTable = {
			(byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd',
			(byte) 'e', (byte) 'f'
	};

	/*
	 * set up the decoding table.
	 */
	protected final byte[] decodingTable = new byte[128];

	protected void initialiseDecodingTable() {
		for (int i = 0; i < decodingTable.length; i++) {
			decodingTable[i] = (byte) 0xff;
		}

		for (int i = 0; i < encodingTable.length; i++) {
			decodingTable[encodingTable[i]] = (byte) i;
		}

		decodingTable['A'] = decodingTable['a'];
		decodingTable['B'] = decodingTable['b'];
		decodingTable['C'] = decodingTable['c'];
		decodingTable['D'] = decodingTable['d'];
		decodingTable['E'] = decodingTable['e'];
		decodingTable['F'] = decodingTable['f'];
	}

	public HexEncoder() {
		initialiseDecodingTable();
	}

	/**
	 * encode the input data producing a Hex output stream.
	 *
	 * @return the number of bytes produced.
	 */
	@Override
	public int encode(byte[] data, int off, int length, OutputStream out) throws IOException {
		for (int i = off; i < (off + length); i++) {
			int v = data[i] & 0xff;

			out.write(encodingTable[(v >>> 4)]);
			out.write(encodingTable[v & 0xf]);
		}

		return length * 2;
	}

}
