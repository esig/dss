package eu.europa.esig.dss.crl;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class BinaryFilteringInputStream extends FilterInputStream {

	/* Reading ? */
	private boolean on = true;

	private final OutputStream os;

	public BinaryFilteringInputStream(InputStream in, OutputStream os) {
		super(in);
		this.os = os;
	}

	@Override
	public int read() throws IOException {
		int ch = in.read();
		if (on && ch != -1) {
			os.write((byte) ch);
		}
		return ch;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int result = in.read(b, off, len);
		if (on && result != -1) {
			os.write(b, off, result);
		}
		return result;
	}

	public void on(boolean on) {
		this.on = on;
	}

}
