package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESTripleLTATest extends AbstractJAdESTestValidation {

    @Test
    public void test() throws Exception {
        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.json");

        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LT);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);

        JAdESService service = new JAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        service.setTspSource(getGoodTsa());
        JAdESSignatureParameters extendParameters = new JAdESSignatureParameters();
        extendParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_LTA);
        extendParameters.setJwsSerializationType(JWSSerializationType.FLATTENED_JSON_SERIALIZATION);
        DSSDocument extendedDocument = service.extendDocument(signedDocument, extendParameters);

        service.setTspSource(getGoodTsaCrossCertification());
        DSSDocument doubleLTADoc = service.extendDocument(extendedDocument, extendParameters);

        service.setTspSource(getSelfSignedTsa());
        DSSDocument tripleLTADoc = service.extendDocument(doubleLTADoc, extendParameters);
        checkSignedDocument(tripleLTADoc);

        Reports reports = verify(tripleLTADoc);

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        DetailedReport detailedReport = reports.getDetailedReport();
        List<String> timestampIds = detailedReport.getTimestampIds();
        assertEquals(4, timestampIds.size());

    }

    private void checkSignedDocument(DSSDocument document) throws JoseException {
        assertTrue(DSSJsonUtils.isJsonDocument(document));
        Map<String, Object> rootStructure = JsonUtil.parseJson(new String(DSSUtils.toByteArray(document)));

        Map<String, Object> unprotected = (Map<String, Object>) rootStructure.get(JWSConstants.HEADER);
        assertTrue(Utils.isMapNotEmpty(unprotected));

        List<Object> unsignedProperties = (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);

        int arcTstCounter = 0;
        int tstVDCounter = 0;

        for (Object property : unsignedProperties) {
            Map<?, ?> map = DSSJsonUtils.parseEtsiUComponent(property);
            Map<?, ?> arcTst = (Map<?, ?>) map.get(JAdESHeaderParameterNames.ARC_TST);
            if (arcTst != null) {
                ++arcTstCounter;
            }
            Map<?, ?> tstVD = (Map<?, ?>) map.get(JAdESHeaderParameterNames.TST_VD);
            if (tstVD != null) {
                List<?> xVals = (List<?>) tstVD.get(JAdESHeaderParameterNames.X_VALS);
                assertTrue(Utils.isCollectionNotEmpty(xVals));
                Map<?, ?> rVals = (Map<?, ?>) tstVD.get(JAdESHeaderParameterNames.R_VALS);
                assertTrue(Utils.isMapNotEmpty(rVals));

                ++tstVDCounter;
            }
        }

        assertEquals(3, arcTstCounter);
        assertEquals(2, tstVDCounter);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_TIMESTAMPS_ONLY);
        return validator;
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        assertEquals(4, diagnosticData.getTimestampList().size());

        int sigTstCounter = 0;
        int arcTstCounter = 0;
        int coveredCerts = 0;
        int coveredRevocation = 0;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++sigTstCounter;

            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                ++arcTstCounter;
                assertTrue(timestampWrapper.getTimestampedCertificates().size() > coveredCerts);
                assertTrue(timestampWrapper.getTimestampedRevocations().size() > coveredRevocation);
                coveredCerts = timestampWrapper.getTimestampedCertificates().size();
                coveredRevocation = timestampWrapper.getTimestampedRevocations().size();
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(3, arcTstCounter);
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
