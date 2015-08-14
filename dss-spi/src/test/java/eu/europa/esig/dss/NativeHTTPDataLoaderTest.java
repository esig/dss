package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public class NativeHTTPDataLoaderTest {

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

	@Test
	public void testGet() {
		NativeHTTPDataLoader dataLoader = new NativeHTTPDataLoader();
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}
}
