package port.org.bouncycastle.util;


/**
 * General array utilities.
 */
public final class Arrays {

	private Arrays() {
		// static class, hide constructor
	}

	public static boolean areEqual(char[] a, char[] b) {
		if (a == b) {
			return true;
		}

		if ((a == null) || (b == null)) {
			return false;
		}

		if (a.length != b.length) {
			return false;
		}

		for (int i = 0; i != a.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}

		return true;
	}

	public static boolean areEqual(byte[] a, byte[] b) {
		if (a == b) {
			return true;
		}

		if ((a == null) || (b == null)) {
			return false;
		}

		if (a.length != b.length) {
			return false;
		}

		for (int i = 0; i != a.length; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}

		return true;
	}

	public static int hashCode(byte[] data) {
		if (data == null) {
			return 0;
		}

		int i = data.length;
		int hc = i + 1;

		while (--i >= 0) {
			hc *= 257;
			hc ^= data[i];
		}

		return hc;
	}

	public static int hashCode(char[] data) {
		if (data == null) {
			return 0;
		}

		int i = data.length;
		int hc = i + 1;

		while (--i >= 0) {
			hc *= 257;
			hc ^= data[i];
		}

		return hc;
	}

	public static byte[] clone(byte[] data) {
		if (data == null) {
			return null;
		}
		byte[] copy = new byte[data.length];

		System.arraycopy(data, 0, copy, 0, data.length);

		return copy;
	}

}
