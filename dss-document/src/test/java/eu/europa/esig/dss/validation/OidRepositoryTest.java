package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.QCStatementOids;

public class OidRepositoryTest {

	@Test
	public void test() {
		assertEquals(CertificatePolicyOids.QCP_LEGAL.getDescription(), OidRepository.getDescription(CertificatePolicyOids.QCP_LEGAL.getOid()));
		assertEquals(QCStatementOids.QC_COMPLIANCE.getDescription(), OidRepository.getDescription(QCStatementOids.QC_COMPLIANCE.getOid()));
		assertNull(OidRepository.getDescription("1.2.3"));
	}

}
