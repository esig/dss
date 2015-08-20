package eu.europa.esig.dss.tsl;

import java.io.File;
import java.net.UnknownHostException;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TrustedListCertificateSourceTest {

	@Test
	public void test1() throws Exception {

		try {
			TrustedListsCertificateSource source = new TrustedListsCertificateSource();
			source.setDataLoader(new CommonsDataLoader());
			KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(new File("src/test/resources/keystore.jks"), "dss-password");
			source.setKeyStoreCertificateSource(keyStoreCertificateSource);
			source.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
			source.setTslRefreshPolicy(TSLRefreshPolicy.NEVER);
			source.setCheckSignature(false);
			source.init();

			Assert.assertTrue(source.getCertificates().size() > 0);
		} catch (Exception e) {
			if (!(e.getCause() instanceof UnknownHostException)) {
				throw e;
			}
			// Internet failure is not test failure
		}

	}

}
