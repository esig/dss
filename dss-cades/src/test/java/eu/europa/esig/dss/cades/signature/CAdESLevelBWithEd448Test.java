package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.xmldsig.jaxb.DigestMethodType;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CAdESLevelBWithEd448Test extends AbstractCAdESTestSignature {

    private static final String HELLO_WORLD = "Hello World";

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(HELLO_WORLD.getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHAKE256_512);

        service = new CAdESService(getOfflineCertificateVerifier());
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
    protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected CAdESSignatureParameters getSignatureParameters() {
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
