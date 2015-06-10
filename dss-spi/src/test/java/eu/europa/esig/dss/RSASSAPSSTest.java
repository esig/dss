package eu.europa.esig.dss;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.BCTokenBuilder;

public class RSASSAPSSTest {

	@Test
	public void test() {

		CertificateToken token = new BCTokenBuilder().buildCertificateToken(this.getClass().getResourceAsStream("/BA-QC-Wurzel-CA-2_PN.txt"));

		Assert.assertTrue(token.isSelfSigned());
		Assert.assertTrue(token.isSignedBy(token));


	}

}
