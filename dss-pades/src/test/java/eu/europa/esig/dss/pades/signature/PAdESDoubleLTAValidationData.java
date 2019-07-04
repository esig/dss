package eu.europa.esig.dss.pades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;

public class PAdESDoubleLTAValidationData extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {

		DSSDocument doc = new InMemoryDocument(PAdESDoubleSignature.class.getResourceAsStream("/sample.pdf"));
		
		// Sign with LT level and GoodTSA
		PAdESService service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		PAdESSignatureParameters params = new PAdESSignatureParameters();
		params.setSigningCertificate(getSigningCert());
		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

		ToBeSigned dataToSign = service.getDataToSign(doc, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument ltLevelDoc = service.signDocument(doc, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltLevelDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> revocationIds = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIds.size());
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(1, timestamps.size());
		assertEquals(3, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(0, timestamps.get(0).getTimestampedRevocationIds().size());
		

		// Extend to LTA level with GoodTSACrossCertification
		service.setTspSource(getGoodTsaCrossCertification());
		
		PAdESSignatureParameters extendParams = new PAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument ltaDoc = service.extendDocument(ltLevelDoc, extendParams);

		validator = SignedDocumentValidator.fromDocument(ltaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		diagnosticData = reports.getDiagnosticData();
		List<String> revocationIdsLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIdsLtaLevel.size());
		for (String id : revocationIds) {
			assertTrue(revocationIdsLtaLevel.contains(id));
		}
		
		timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		assertEquals(3, timestamps.get(0).getTimestampedObjects().size());
		assertEquals(0, timestamps.get(0).getTimestampedRevocationIds().size());
		
		assertEquals(11, timestamps.get(1).getTimestampedObjects().size());
		assertEquals(2, timestamps.get(1).getTimestampedRevocationIds().size());
		
		
		// Extend to second LTA level with GoodTSACrossCertification
		// This must force addition of missing revocation data to the previously created timestamp
		DSSDocument doubleLtaDoc = service.extendDocument(ltaDoc, extendParams);
		
		// doubleLtaDoc.save("target/doubleLtaDoc.pdf");

		validator = SignedDocumentValidator.fromDocument(doubleLtaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		// reports.print();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(2, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		diagnosticData = reports.getDiagnosticData();
		
		timestamps = diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		
		for (TimestampWrapper timestamp : timestamps) {
			CertificateWrapper signingCertificate = timestamp.getSigningCertificate();
			assertNotNull(signingCertificate);
			assertTrue(signingCertificate.isRevocationDataAvailable());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataFound());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataIntact());
		}
		
		TimestampWrapper timestampWrapper = timestamps.get(0);
		assertEquals(3, timestampWrapper.getTimestampedObjects().size());
		assertEquals(0, timestampWrapper.getTimestampedRevocationIds().size());
		
		timestampWrapper = timestamps.get(1);
		assertEquals(11, timestampWrapper.getTimestampedObjects().size());
		assertEquals(2, timestampWrapper.getTimestampedRevocationIds().size());
		
		timestampWrapper = timestamps.get(2);
		assertEquals(18, timestampWrapper.getTimestampedObjects().size());
		assertEquals(3, timestampWrapper.getTimestampedRevocationIds().size());
		
		
		diagnosticData = reports.getDiagnosticData();
		List<String> revocationIdsDoubleLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(3, revocationIdsDoubleLtaLevel.size());
		for (String id : revocationIdsLtaLevel) {
			assertTrue(revocationIdsDoubleLtaLevel.contains(id));
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(3, signature.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_DSS).size());
		assertEquals(3, signature.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_VRI).size());
		
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}


}
