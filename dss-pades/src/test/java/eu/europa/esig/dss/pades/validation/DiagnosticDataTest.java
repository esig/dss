package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.RevocationOriginType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DiagnosticDataTest extends PKIFactoryAccess {

	@Test
	public void pdfSignatureDictionaryTest() {
		
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/AD-RB.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		Set<SignatureWrapper> signatures = diagnosticData.getAllSignatures();
		assertNotNull(signatures);
		for (SignatureWrapper signature : signatures) {
			List<BigInteger> byteRange = signature.getSignatureByteRange();
			assertNotNull(byteRange);
			assertEquals(4, byteRange.size());
			assertEquals(-1, byteRange.get(1).compareTo(byteRange.get(2)));
		}
		
	}
	
	@Test
	public void revocationOriginTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/HU_POL/Signature-P-HU_POL-3.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		int xmlRevocationValuesOriginCounter = 0;
		int xmlTimestampRevocationDataOriginCounter = 0;
		int dssDictionatyOriginCounter = 0;
		Set<RevocationWrapper> revocationData = diagnosticData.getAllRevocationData();
		for (RevocationWrapper revocation : revocationData) {
			assertNotNull(revocation.getSource());
			assertNotNull(revocation.getOrigin());
			if (RevocationOriginType.INTERNAL_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				xmlRevocationValuesOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES.equals(revocation.getOrigin())) {
				xmlTimestampRevocationDataOriginCounter++;
			}
			if (RevocationOriginType.INTERNAL_DSS.equals(revocation.getOrigin())) {
				dssDictionatyOriginCounter++;
			}
		}
		assertEquals(0, xmlRevocationValuesOriginCounter);
		assertEquals(0, xmlTimestampRevocationDataOriginCounter);
		assertEquals(7, dssDictionatyOriginCounter);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
