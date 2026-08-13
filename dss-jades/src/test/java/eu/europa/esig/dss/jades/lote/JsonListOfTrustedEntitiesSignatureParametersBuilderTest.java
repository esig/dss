package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.signature.AbstractJAdESTestSignature;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class JsonListOfTrustedEntitiesSignatureParametersBuilderTest extends AbstractJAdESTestSignature {

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private JAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/lote/lote-valid.json"));
        service = new JAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        JsonListOfTrustedEntitiesSignatureParametersBuilder signatureParametersBuilder = getSignatureParametersBuilder();
        signatureParametersBuilder.assertConfigurationIsValid();
        signatureParameters = signatureParametersBuilder.build();
        return super.sign();
    }

    protected JsonListOfTrustedEntitiesSignatureParametersBuilder getSignatureParametersBuilder() {
        return new JsonListOfTrustedEntitiesSignatureParametersBuilder(getSigningCert(), documentToSign);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        try {
            JWS jws = new JWSCompactSerializationParser(byteArray).parse();
            assertNotNull(jws);
            assertNotNull(jws.getHeaders());
            assertNotNull(jws.getUnverifiedPayloadBytes());
            assertNotNull(jws.getSignatureValue());
            assertTrue(Utils.isMapEmpty(jws.getUnprotected()));

        } catch (Exception e) {
            fail(e);
        }
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
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}