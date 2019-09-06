package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

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
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		TimestampToken timestampToken = advancedSignature.getSignatureTimestamps().get(0);
		assertEquals(0, timestampToken.getCRLSource().getCRLBinaryList().size());
		assertEquals(0, timestampToken.getOCSPSource().getOCSPResponsesList().size());
		
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
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		TimestampToken archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(0, archiveTimestamp.getCRLSource().getCRLBinaryList().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getOCSPResponsesList().size());
		
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
		
		assertEquals(1, advancedSignature.getCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getOCSPSource().getOCSPResponsesList().size());
		
		assertEquals(2, advancedSignature.getCompleteCRLSource().getCRLBinaryList().size());
		assertEquals(1, advancedSignature.getCompleteOCSPSource().getOCSPResponsesList().size());
		
		archiveTimestamp = advancedSignature.getArchiveTimestamps().get(0);
		assertEquals(1, archiveTimestamp.getCRLSource().getCRLBinaryList().size());
		assertEquals(0, archiveTimestamp.getOCSPSource().getOCSPResponsesList().size());
		
		diagnosticData = reports.getDiagnosticData();
		
		List<TimestampWrapper> allTimestamps = diagnosticData.getTimestampList();
		assertNotNull(allTimestamps);
		assertEquals(3, allTimestamps.size());
		
		for (TimestampWrapper timestamp : allTimestamps) {
			CertificateWrapper signingCertificate = timestamp.getSigningCertificate();
			assertNotNull(signingCertificate);
			assertTrue(signingCertificate.isRevocationDataAvailable());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataFound());
			assertTrue(timestamp.getDigestMatchers().get(0).isDataIntact());
		}
		
		assertEquals(0, allTimestamps.get(0).getTimestampedRevocationIds().size());
		assertEquals(2, allTimestamps.get(1).getTimestampedRevocationIds().size());
		assertEquals(3, allTimestamps.get(2).getTimestampedRevocationIds().size());
		
		List<String> revocationIdsDoubleLtaLevel = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId()).getRevocationIds();
		assertEquals(3, revocationIdsDoubleLtaLevel.size());
		for (String id : revocationIdsLtaLevel) {
			assertTrue(revocationIdsDoubleLtaLevel.contains(id));
		}
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		assertEquals(1, signature.getRevocationIdsByOrigin(RevocationOrigin.TIMESTAMP_REVOCATION_VALUES).size());
		
		ValidationReportType etsiValidationReportJaxb = reports.getEtsiValidationReportJaxb();
		List<ValidationObjectType> validationObjects = etsiValidationReportJaxb.getSignatureValidationObjects().getValidationObject();
		int validationReportTimestampCounter = 0;
		for (ValidationObjectType validationObject : validationObjects) {
			
			POEProvisioningType poeProvisioning = validationObject.getPOEProvisioning();
			if (poeProvisioning != null) {
				
				List<String> timestampedObjectIds = new ArrayList<String>();
				
				assertNotNull(poeProvisioning.getPOETime());
				assertNotNull(poeProvisioning.getSignatureReference());
				
				validationReportTimestampCounter++;
				List<VOReferenceType> references = poeProvisioning.getValidationObject();
				assertTrue(Utils.isCollectionNotEmpty(references));
				
				for (VOReferenceType reference : references) {
					Object voReference = reference.getVOReference().get(0);
					assertNotNull(voReference);
					assertTrue(voReference instanceof ValidationObjectType);
					ValidationObjectType validationObjectReference = (ValidationObjectType) voReference;
					String id = validationObjectReference.getId();
					assertNotNull(id);
					assertFalse(timestampedObjectIds.contains(id));
					timestampedObjectIds.add(id);
				}
				
				assertTrue(Utils.isCollectionNotEmpty(timestampedObjectIds));
			}
		}
		assertEquals(3, validationReportTimestampCounter);
		
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}
