package eu.europa.esig.dss.client.http.commons;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public class CommonsDataLoaderTest {

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

	@Test
	public void testGet() {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		NativeHTTPDataLoader dataLoader2 = new NativeHTTPDataLoader();
		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD);

		assertTrue(Arrays.equals(bytesArray, bytesArrays2));

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

}
