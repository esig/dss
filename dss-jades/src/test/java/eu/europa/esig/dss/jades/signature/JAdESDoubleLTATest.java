package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jades.JAdESArchiveTimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;

public class JAdESDoubleLTATest extends AbstractJAdESTestValidation {
	
	@Test
	public void test() throws IOException {
		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.json");

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        JAdESService service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

         signedDocument.save("target/signed.json");
         
        checkOnSigned(signedDocument, 0);

        service.setTspSource(getGoodTsaCrossCertification());

        JAdESSignatureParameters extendParameters = new JAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extendParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);
        
        checkOnSigned(extendedDocument, 1);
        
        JAdESTimestampParameters archiveTimestampParameters = new JAdESTimestampParameters();
        archiveTimestampParameters.setArchiveTimestampType(JAdESArchiveTimestampType.TIMESTAMPED_PREVIOUS_ARC_TST);
        extendParameters.setArchiveTimestampParameters(archiveTimestampParameters);
        
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);
        
         doubleLTADoc.save("target/doubleLTA.json");
         
        checkOnSigned(doubleLTADoc, 2);
        
        Reports reports = verify(doubleLTADoc);
        
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        
        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(3, timestampIds.size());
        
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        
        int archiveTimestampCounter = 0;
        for (String id : timestampIds) {
            assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(id));
            TimestampWrapper timestamp = diagnosticData.getTimestampById(id);
            if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
            	assertEquals(archiveTimestampCounter == 0 ? ArchiveTimestampType.JAdES_ALL : ArchiveTimestampType.JAdES_PREVIOUS_ARC_TST, 
            			timestamp.getArchiveTimestampType());
            	archiveTimestampCounter++;
            }
        }
        assertEquals(2, archiveTimestampCounter);
        
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertContainsAllRevocationData(signature.getCertificateChain());
        for (TimestampWrapper timestamp : diagnosticData.getTimestampList()) {
        	assertContainsAllRevocationData(timestamp.getCertificateChain());
        }
        for (RevocationWrapper revocation : diagnosticData.getAllRevocationData()) {
        	assertContainsAllRevocationData(revocation.getCertificateChain());
        }
        
	}
	
	@SuppressWarnings("unchecked")
	private void checkOnSigned(DSSDocument document, int expectedArcTsts) {
		assertTrue(JAdESUtils.isJsonDocument(document));
		try {
			byte[] binaries = DSSUtils.toByteArray(document);
			Map<String, Object> rootStructure = JsonUtil.parseJson(new String(binaries));
			
			String firstEntryName = rootStructure.keySet().iterator().next();
			assertEquals(JWSConstants.PAYLOAD, firstEntryName);
			
			String payload = (String) rootStructure.get(firstEntryName);
			assertNotNull(payload);
			assertTrue(Utils.isArrayNotEmpty(JAdESUtils.fromBase64Url(payload)));
			
			String header = (String) rootStructure.get(JWSConstants.PROTECTED);
			assertNotNull(header);
			assertTrue(Utils.isArrayNotEmpty(JAdESUtils.fromBase64Url(header)));
			
			String signatureValue = (String) rootStructure.get(JWSConstants.SIGNATURE);
			assertNotNull(signatureValue);
			assertTrue(Utils.isArrayNotEmpty(JAdESUtils.fromBase64Url(signatureValue)));
			
			Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get(JWSConstants.HEADER);
			assertTrue(Utils.isMapNotEmpty(unprotected));
			
			List<Object> unsignedProperties = (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);
			
			int xValsCounter = 0;
			int rValsCounter = 0;
			int arcTstCounter = 0;
			int tstVdCounter = 0;
			
			for (Object property : unsignedProperties) {
				Map<String, Object> map = (Map<String, Object>) property;
				List<?> xVals = (List<?>) map.get(JAdESHeaderParameterNames.X_VALS);
				if (xVals != null) {
					++xValsCounter;
				}
				Map<?, ?> rVals = (Map<?, ?>) map.get(JAdESHeaderParameterNames.R_VALS);
				if (rVals != null) {
					++rValsCounter;
				}
				Map<?, ?> arcTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.ARC_TST);
				if (arcTst != null) {
					++arcTstCounter;
					Map<?, ?> tstContainer = (Map<?, ?>) arcTst.get(JAdESHeaderParameterNames.TST_CONTAINER);
					assertNotNull(tstContainer);
					List<?> tsTokens = (List<?>) tstContainer.get(JAdESHeaderParameterNames.TS_TOKENS);
					assertEquals(1, tsTokens.size());
				}
				Map<?, ?> tstVd = (Map<?, ?>) map.get(JAdESHeaderParameterNames.TST_VD);
				if (tstVd != null) {
					++tstVdCounter;
				}
			}

			assertEquals(1, xValsCounter);
			assertEquals(1, rValsCounter);
			assertEquals(expectedArcTsts, arcTstCounter);
			assertEquals(expectedArcTsts > 0 ? expectedArcTsts - 1 : 0, tstVdCounter);

		} catch (JoseException e) {
			fail("Unable to parse the signed file : " + e.getMessage());
		}
	}
	
	private void assertContainsAllRevocationData(List<CertificateWrapper> certificateChain) {
        for (CertificateWrapper certificate : certificateChain) {
        	if (certificate.isTrusted()) {
        		break;
        	}
        	assertTrue(certificate.isRevocationDataAvailable() || certificate.isSelfSigned(), 
        			"Certificate with id : [" + certificate.getId() + "] does not have a revocation data!");
        }
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}
	
	@Override
	public void validate() {
		// do nothing
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return null;
	}

}
