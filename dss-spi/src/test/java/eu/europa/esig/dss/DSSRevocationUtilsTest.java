package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

public class DSSRevocationUtilsTest {

	@Test
	public void testRevocationReasonFromCRL() throws Exception {
		X509CRL crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/LTGRCA.crl"));
		assertNotNull(crl);
		assertTrue(CollectionUtils.isNotEmpty(crl.getRevokedCertificates()));
		for (X509CRLEntry entry: crl.getRevokedCertificates()) {
			String revocationReason = DSSRevocationUtils.getRevocationReason(entry);
			assertTrue(StringUtils.isNotEmpty(revocationReason));
		}

		crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/belgium2.crl"));
		assertNotNull(crl);
		assertTrue(CollectionUtils.isEmpty(crl.getRevokedCertificates()));
	}
}
