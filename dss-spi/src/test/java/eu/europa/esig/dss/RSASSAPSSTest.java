package eu.europa.esig.dss;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.x509.CertificateToken;

public class RSASSAPSSTest {

	@Test
	public void test() {

		CertificateToken token = DSSUtils.loadCertificate(this.getClass().getResourceAsStream("/BA-QC-Wurzel-CA-2_PN.txt"));

		Assert.assertTrue(token.isSelfSigned());
		Assert.assertTrue(token.isSignedBy(token));


	}

}
