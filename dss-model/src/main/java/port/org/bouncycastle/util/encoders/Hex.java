package port.org.bouncycastle.util.encoders;

import java.io.ByteArrayOutputStream;

/**
 * Utility class for converting hex data to bytes and back again.
 */
public class Hex {
	private static final Encoder encoder = new HexEncoder();

	/**
	 * encode the input data producing a Hex encoded byte array.
	 *
	 * @return a byte array containing the Hex encoded data.
	 */
	public static byte[] encode(byte[] data) {
		return encode(data, 0, data.length);
	}

	/**
	 * encode the input data producing a Hex encoded byte array.
	 *
	 * @return a byte array containing the Hex encoded data.
	 */
	public static byte[] encode(byte[] data, int off, int length) {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		try {
			encoder.encode(data, off, length, bOut);
		} catch (Exception e) {
			throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
		}

		return bOut.toByteArray();
	}

}
