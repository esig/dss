package eu.europa.esig.dss.client.http;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;

public class NativeHTTPDataLoaderTest {

	private static final String HTTP_URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";
	private static final String FILE_URL_TO_LOAD = "file:src/test/resources/belgiumrs2.crt";

	@Test
	public void testHttpGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(HTTP_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void testFileGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(FILE_URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void testGetBiggerThanMaxSize() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setMaxInputSize(1);
		
		try {
			dataLoader.get(FILE_URL_TO_LOAD);
			fail();
		} catch (DSSException dssEx) {
		}
	}

	@Test
	public void testGetTimeout() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		dataLoader.setTimeout(1);
		
		try {
			dataLoader.get(HTTP_URL_TO_LOAD);
			fail();
		} catch (DSSException dssEx) {
		}
	}
}
