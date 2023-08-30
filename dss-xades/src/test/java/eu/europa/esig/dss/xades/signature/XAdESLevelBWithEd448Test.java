package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.xmldsig.jaxb.DigestMethodType;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XAdESLevelBWithEd448Test extends AbstractXAdESTestSignature {

    private static final String HELLO_WORLD = "Hello World";

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());
        signatureParameters = initSignatureParameters();
        service = new XAdESService(getOfflineCertificateVerifier());
    }

    private XAdESSignatureParameters initSignatureParameters() {
        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHAKE256_512);
        return signatureParameters;
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::sign);
        assertEquals("The Reference DigestAlgorithm 'SHAKE256_512' is not supported for XAdES creation! " +
                "Define another algorithm within #setReferenceDigestAlgorithm method.", exception.getMessage());

        signatureParameters = initSignatureParameters();
        signatureParameters.setReferenceDigestAlgorithm(DigestAlgorithm.SHA256);

        return super.sign();
    }

    @Override
    protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
        assertNotNull(signatureIdentifier);
        assertNotNull(signatureIdentifier.getId());
        assertNotNull(signatureIdentifier.getDigestAlgAndValue());
        DigestMethodType digestMethod = signatureIdentifier.getDigestAlgAndValue().getDigestMethod();
        assertNotNull(digestMethod);
        assertNotNull(digestMethod.getAlgorithm());
        assertEquals(DigestAlgorithm.SHAKE256_512, DigestAlgorithm.forOID(DSSUtils.getOidCode(digestMethod.getAlgorithm())));
        assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestValue());
        assertNotNull(signatureIdentifier.getSignatureValue());
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

    @Override
    protected String getSigningAlias() {
        return ED448_GOOD_USER;
    }

}
