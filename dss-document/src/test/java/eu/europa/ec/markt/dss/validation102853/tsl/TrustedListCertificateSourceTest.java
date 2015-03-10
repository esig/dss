package eu.europa.ec.markt.dss.validation102853.tsl;

import java.net.UnknownHostException;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;

public class TrustedListCertificateSourceTest {

	@Test
	public void test1() throws Exception {

		try {
			TrustedListsCertificateSource source = new TrustedListsCertificateSource();
			source.setDataLoader(new CommonsDataLoader());
			source.setLotlCertificate("classpath://ec.europa.eu.crt");
			source.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
			source.setTslRefreshPolicy(TSLRefreshPolicy.NEVER);
			source.setCheckSignature(false);
			source.init();

			Assert.assertTrue(source.getCertificates().size() > 0);
		} catch (Exception e) {
			if(!(e.getCause() instanceof UnknownHostException)) {
				throw e;
			}
			// Internet failure is not test failure
		}

	}

}
