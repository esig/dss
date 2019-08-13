package eu.europa.esig.dss.crl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class AbstractCRLParserTestUtils {
	
	protected byte[] toByteArray(InputStream is) throws IOException {
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			int nRead;
			byte[] data = new byte[4096];
			while ((nRead = is.read(data, 0, data.length)) != -1) {
			  buffer.write(data, 0, nRead);
			}
			return buffer.toByteArray();
		}
	}

}
