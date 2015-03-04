package eu.europa.ec.markt.dss.validation102853.tsl;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;

public class TrustedListCertificateSourceTest {
	
	@Test
	public void test1() throws Exception {
		
		TrustedListsCertificateSource source = new TrustedListsCertificateSource();
		source.setDataLoader(new CommonsDataLoader());
		source.setLotlCertificate("classpath://ec.europa.eu.crt");
		source.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		source.setTslRefreshPolicy(TSLRefreshPolicy.NEVER);
		source.setCheckSignature(false);
		source.init();
		
		Assert.assertTrue(source.getCertificates().size() > 0);

	}
	
}
