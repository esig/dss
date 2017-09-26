package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;
import org.junit.Test;

import eu.europa.esig.dss.DSSException;

public class PemToDerConverterTest {

	@Test(expected = DSSException.class)
	public void testException() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PemToDerConverter.convert(baos);
	}

	@Test
	public void pemFile() throws IOException {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/belgium2.pem.crl")) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			Streams.pipeAll(is, baos);
			ByteArrayOutputStream convert = PemToDerConverter.convert(baos);
			byte[] converted = convert.toByteArray();
			assertTrue(converted != null && converted.length > 0);
		}
	}

}
