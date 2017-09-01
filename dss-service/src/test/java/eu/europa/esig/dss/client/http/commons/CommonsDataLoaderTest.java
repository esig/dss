package eu.europa.esig.dss.client.http.commons;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CommonsDataLoaderTest {

	private static final String URL_TO_LOAD = "http://certs.eid.belgium.be/belgiumrs2.crt";

	private CommonsDataLoader dataLoader = new CommonsDataLoader();

	@Test
	public void testGet() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD);

		NativeHTTPDataLoader dataLoader2 = new NativeHTTPDataLoader();
		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD);

		assertTrue(Arrays.equals(bytesArray, bytesArrays2));

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	@Ignore("no proxy on the test environment")
	public void proxyTest() {
		byte[] bytesArray = dataLoader.get(URL_TO_LOAD); // without proxy

		CommonsDataLoader dataLoader2 = new CommonsDataLoader();

		ProxyConfig proxyConfig = new ProxyConfig();
		ProxyProperties proxyProperties = new ProxyProperties();
		proxyProperties.setHost("localhost");
		proxyProperties.setPort(3128);
		proxyProperties.setUser("someDomain\\Teszt"); //ntlm
		proxyProperties.setPassword("Teszt123");
		proxyConfig.setHttpProperties(proxyProperties);
		proxyConfig.setHttpsProperties(proxyProperties);
		dataLoader2.setProxyConfig(proxyConfig);

		byte[] bytesArrays2 = dataLoader2.get(URL_TO_LOAD); // with proxy

		assertTrue(Arrays.equals(bytesArray, bytesArrays2));

		CertificateToken certificate = DSSUtils.loadCertificate(bytesArray);
		assertNotNull(certificate);
	}

	@Test
	public void ldapTest1() {
		String url = "ldap://x500.gov.si/ou=sigen-ca,o=state-institutions,c=si?certificateRevocationList?base";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

	@Test
	public void ldapTest2() {
		String url = "ldap://postarca.posta.si/ou=POSTArCA,o=POSTA,c=SI?certificateRevocationList";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

	@Test
	public void ldapTest3() {
		String url = "ldap://acldap.nlb.si/o=ACNLB,c=SI?certificateRevocationList";
		assertTrue(Utils.isArrayNotEmpty(dataLoader.get(url)));
	}

}
