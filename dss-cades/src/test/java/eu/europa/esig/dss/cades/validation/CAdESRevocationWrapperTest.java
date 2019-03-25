package eu.europa.esig.dss.cades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.RevocationOriginType;
import eu.europa.esig.dss.validation.RevocationType;
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
		int revocationSignatureOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getRevocationType());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.SIGNATURE.equals(revocation.getOrigin())) {
				revocationSignatureOriginCounter++;
			}
		}
		assertEquals(2, revocationSignatureOriginCounter);
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_DSS).size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
