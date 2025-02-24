package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedListV5SignatureParametersBuilderInvalidTLTest extends AbstractXAdESTestSignature {

    private static final String REFERENCE_ID = "dss-tl-id-1";
    private static final DigestAlgorithm REFERENCE_DIGEST_ALGORITHM = DigestAlgorithm.SHA512;

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/fi-v5-invalid-no-sig.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        TrustedListV5SignatureParametersBuilder signatureParametersBuilder = getSignatureParametersBuilder();
        Exception exception = assertThrows(IllegalInputException.class, signatureParametersBuilder::assertConfigurationIsValid);
        assertTrue(exception.getMessage().contains("ServiceSupplyPoint"));
    }

    protected TrustedListV5SignatureParametersBuilder getSignatureParametersBuilder() {
        return new TrustedListV5SignatureParametersBuilder(getSigningCert(), documentToSign)
                .setReferenceId(REFERENCE_ID)
                .setReferenceDigestAlgorithm(REFERENCE_DIGEST_ALGORITHM);
    }

    @Override
    protected String getCanonicalizationMethod() {
        return CanonicalizationMethod.EXCLUSIVE;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

}
