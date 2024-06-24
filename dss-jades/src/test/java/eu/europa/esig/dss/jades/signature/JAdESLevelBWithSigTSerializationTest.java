package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESSigningTimeType;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSConstants;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class JAdESLevelBWithSigTSerializationTest extends AbstractJAdESTestSignature {

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    public void init() throws Exception {
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnNotYetValidCertificate(new SilentOnStatusAlert());
        service = new JAdESService(certificateVerifier);

        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(DSSUtils.getUtcDate(2024, Calendar.JANUARY, 1)); // shall be before 2025-05-15
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);

        signatureParameters.setJadesSigningTimeType(JAdESSigningTimeType.SIG_T);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        assertTrue(DSSJsonUtils.isJsonDocument(new InMemoryDocument(byteArray)));
        try {
            Map<String, Object> rootStructure = JsonUtil.parseJson(new String(byteArray));

            String payload = (String) rootStructure.get(JWSConstants.PAYLOAD);
            assertNotNull(payload);
            assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(payload)));

            List<Map<String, Object>> signaturesList = (List<Map<String, Object>>) rootStructure.get(JWSConstants.SIGNATURES);
            assertTrue(Utils.isCollectionNotEmpty(signaturesList));
            assertEquals(1, signaturesList.size());

            Map<String, Object> signature = signaturesList.get(0);
            String header = (String) signature.get(JWSConstants.PROTECTED);
            assertNotNull(header);
            byte[] bytes = DSSJsonUtils.fromBase64Url(header);
            assertNotNull(bytes);
            Map<String, Object> protectedHeaderMap = JsonUtil.parseJson(new String(bytes));
            assertTrue(Utils.isMapNotEmpty(protectedHeaderMap));

            Object sigT = protectedHeaderMap.get(JAdESHeaderParameterNames.SIG_T);
            assertNotNull(sigT);

            String signatureValue = (String) signature.get(JWSConstants.SIGNATURE);
            assertNotNull(signatureValue);
            assertTrue(Utils.isArrayNotEmpty(DSSJsonUtils.fromBase64Url(signatureValue)));

        } catch (JoseException e) {
            fail("Unable to parse the signed file : " + e.getMessage());
        }

    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
