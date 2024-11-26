package eu.europa.esig.dss.xades.tsl;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.AbstractXAdESTestSignature;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TrustedListV6SignatureParametersBuilderInvalidTLVersionTest extends AbstractXAdESTestSignature {

    private static final String REFERENCE_ID = "dss-tl-id-1";
    private static final DigestAlgorithm REFERENCE_DIGEST_ALGORITHM = DigestAlgorithm.SHA512;

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() {
        documentToSign = new FileDocument(new File("src/test/resources/eu-lotl-no-sig.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());
    }

    @Test
    @Override
    public void signAndVerify() {
        TrustedListV6SignatureParametersBuilder signatureParametersBuilder = getSignatureParametersBuilder();
        Exception exception = assertThrows(IllegalInputException.class, signatureParametersBuilder::assertConfigurationIsValid);
        assertEquals("XML Trusted List failed the validation : TSL Version '5' found in the XML Trusted List " +
                "does not correspond to the target version defined by the builder '6'! " +
                "Please modify the document or change to the appropriate builder.", exception.getMessage());
    }

    protected TrustedListV6SignatureParametersBuilder getSignatureParametersBuilder() {
        return new TrustedListV6SignatureParametersBuilder(getSigningCert(), documentToSign)
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
