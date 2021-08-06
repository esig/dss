package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.DocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESSignWithRevokedCertTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello World".getBytes());
        service = new CAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    private void initSignatureParameters() {
        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
    }

    @Test
    public void signBRevokedAndSignBGoodUserTest() {
        signingAlias = REVOKED_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = GOOD_USER;
        initSignatureParameters();

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentValidator validator = new CMSDocumentValidator(doubleSigned);
        assertEquals(2, validator.getSignatures().size());
    }

    @Test
    public void signBRevokedAndSignLTGoodUserTest() {
        signingAlias = REVOKED_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = GOOD_USER;
        initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentValidator validator = new CMSDocumentValidator(doubleSigned);
        assertEquals(2, validator.getSignatures().size());
    }

    @Test
    public void signBGoodUserAndSignBRevokedTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();

        DSSDocument doubleSigned = sign();
        assertNotNull(doubleSigned);

        DocumentValidator validator = new CMSDocumentValidator(doubleSigned);
        assertEquals(2, validator.getSignatures().size());
    }

    @Test
    public void signBGoodUserAndSignLTRevokedTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);

        Exception exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));
    }

    @Test
    public void signBWithRevocationCheckEnabledTest() {
        signingAlias = GOOD_USER;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);
        documentToSign = sign();

        signingAlias = REVOKED_USER;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);

        Exception exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        signingAlias = GOOD_USER_UNKNOWN;
        initSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(true);

        exception = assertThrows(AlertException.class, () -> sign());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));
    }

    @Override
    public void signAndVerify() {
        // do nothing
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
        return signingAlias;
    }

}
