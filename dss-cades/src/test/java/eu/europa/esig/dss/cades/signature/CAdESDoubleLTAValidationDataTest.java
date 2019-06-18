package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class CAdESDoubleLTAValidationDataTest extends PKIFactoryAccess {
	
	@Test
	public void test() throws Exception {

		DSSDocument doc = new InMemoryDocument("Hello".getBytes(StandardCharsets.UTF_8));
		
		// Sign with LT level and GoodTSA
		CAdESService service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());

		CAdESSignatureParameters params = new CAdESSignatureParameters();
		params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		params.setSigningCertificate(getSigningCert());
		params.setCertificateChain(getCertificateChain());
		params.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

		ToBeSigned dataToSign = service.getDataToSign(doc, params);

		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument ltLevelDoc = service.signDocument(doc, params, signatureValue);

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltLevelDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		AdvancedSignature advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllOCSPIdentifiers().size());
		
		TimestampToken timestampToken = advancedSignature.getSignatureTimestamps().get(0);
		assertEquals(0, timestampToken.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(0, timestampToken.getOCSPSource().getAllOCSPIdentifiers().size());
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<String> revocationIds = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIds.size());
		
		// ltLevelDoc.save("target/ltLevelDoc.pkcs7");
		

		// Extend to LTA level with GoodTSACrossCertification
		service.setTspSource(getGoodTsaCrossCertification());

		CAdESSignatureParameters extendParams = new CAdESSignatureParameters();
		extendParams.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
		extendParams.setSigningCertificate(getSigningCert());
		DSSDocument ltaDoc = service.extendDocument(ltLevelDoc, extendParams);
		
		// ltaDoc.save("target/ltaDoc.pkcs7");

		validator = SignedDocumentValidator.fromDocument(ltaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(1, advancedSignature.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllOCSPIdentifiers().size());
		
		TimestampToken archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(0, archiveTimestamp.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getAllOCSPIdentifiers().size());
		
		extendParams.setCertificateChain(getCertificateChain());
		
		diagnosticData = reports.getDiagnosticData();
		List<String> revocationIdsLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(2, revocationIdsLtaLevel.size());
		for (String id : revocationIds) {
			assertTrue(revocationIdsLtaLevel.contains(id));
		}
		
		
		// Extend to second LTA level with GoodTSACrossCertification
		// This must force addition of missing revocation data to the previously created timestamp
		DSSDocument doubleLtaDoc = service.extendDocument(ltaDoc, extendParams);
		
		// doubleLtaDoc.save("target/doubleLtaDoc.pkcs7");

		validator = SignedDocumentValidator.fromDocument(doubleLtaDoc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		// reports.print();
		
		signatures = validator.getSignatures();
		advancedSignature = signatures.get(0);
		
		assertEquals(2, advancedSignature.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(1, advancedSignature.getOCSPSource().getAllOCSPIdentifiers().size());
		
		assertEquals(2, advancedSignature.getCompleteCRLSource().getAllCRLIdentifiers().size());
		assertEquals(1, advancedSignature.getCompleteOCSPSource().getAllOCSPIdentifiers().size());
		
		archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(1, archiveTimestamp.getCRLSource().getAllCRLIdentifiers().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getAllOCSPIdentifiers().size());
		
		diagnosticData = reports.getDiagnosticData();
		
		Set<TimestampWrapper> allTimestamps = diagnosticData.getAllTimestamps();
		assertNotNull(allTimestamps);
		assertEquals(3, allTimestamps.size());
		
		for (TimestampWrapper timestamp : allTimestamps) {
			CertificateWrapper signingCertificate = timestamp.getSigningCertificate();
			assertNotNull(signingCertificate);
			assertTrue(signingCertificate.isRevocationDataAvailable());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataFound());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataIntact());
		}
		
		diagnosticData = reports.getDiagnosticData();
		List<String> revocationIdsDoubleLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(3, revocationIdsDoubleLtaLevel.size());
		for (String id : revocationIdsLtaLevel) {
			assertTrue(revocationIdsDoubleLtaLevel.contains(id));
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(1, signature.getRevocationIdsByOrigin(XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
		
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}
