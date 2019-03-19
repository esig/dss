package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.RevocationOriginType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;

public class CAdESRevocationWrapperTest extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/HU_POL/Signature-C-HU_POL-3.p7m");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		int revocationValuesOriginCounter = 0;
		int timestampRevocationDataOriginCounter = 0;
		int dssDictionatyOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getSource());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.INTERNAL_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				revocationValuesOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				timestampRevocationDataOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_DSS.equals(revocation.getOrigin())) {
				dssDictionatyOriginCounter++;
			}
		}
		assertEquals(2, revocationValuesOriginCounter);
		assertEquals(0, timestampRevocationDataOriginCounter);
		assertEquals(0, dssDictionatyOriginCounter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
