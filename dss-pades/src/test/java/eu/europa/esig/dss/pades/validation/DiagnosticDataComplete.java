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
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class DiagnosticDataComplete extends PKIFactoryAccess {

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

		assertEquals(3, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL).size());
		assertEquals(4, diagnosticData.getAllRevocationForSignatureByType(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_DSS).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(4, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(diagnosticData.getFirstSignatureId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_DSS).size());
	}
	
	@Test
	public void multiSignedDocRevocationRefTest() throws Exception {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/SK/Signature-P-SK-6.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// report.print();
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		
		SignatureWrapper signatureOne = signatures.get(0);
		assertEquals(3, diagnosticData.getAllRevocationForSignature(signatureOne.getId()).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByType(signatureOne.getId(), RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signatureOne.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureOne.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_DSS).size());
		
		SignatureWrapper signatureTwo = signatures.get(1);
		assertEquals(3, diagnosticData.getAllRevocationForSignature(signatureTwo.getId()).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByType(signatureTwo.getId(), RevocationType.CRL).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signatureTwo.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(3, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signatureTwo.getId(), 
				RevocationType.CRL, RevocationOriginType.INTERNAL_DSS).size());
	}
	
	@Test
	public void dssAndVriTest() {
		DSSDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/plugtest/esig2014/ESIG-PAdES/BG_BOR/Signature-P-BG_BOR-2.pdf"));
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports report = validator.validateDocument();
		// System.out.println(report.getXmlDiagnosticData().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
		DiagnosticData diagnosticData = report.getDiagnosticData();
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertNotNull(signatures);
		
		SignatureWrapper signature = signatures.get(0);
		assertEquals(2, diagnosticData.getAllRevocationForSignature(signature.getId()).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByType(signature.getId(), RevocationType.CRL).size());
		assertEquals(2, diagnosticData.getAllRevocationForSignatureByType(signature.getId(), RevocationType.OCSP).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_DSS).size());
		assertEquals(1, diagnosticData.getAllRevocationForSignatureByTypeAndOrigin(signature.getId(), 
				RevocationType.OCSP, RevocationOriginType.INTERNAL_VRI).size());
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
