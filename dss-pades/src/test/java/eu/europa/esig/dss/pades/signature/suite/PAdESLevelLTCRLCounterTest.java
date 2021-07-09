package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PAdESLevelLTCRLCounterTest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CertificateVerifier certificateVerifier;
    private Date signingTime;

    private int numberOfCalls;

    @BeforeEach
    public void init() throws Exception {
        originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        signingTime = new Date();

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        signatureParameters.bLevel().setSigningDate(signingTime);

        certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setCrlSource(new OnlineCRLSourceCounter());
        certificateVerifier.setAIASource(new DefaultAIASource(getFileCacheDataLoader()));

        service = new PAdESService(certificateVerifier);

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(signingTime);
        calendar.add(Calendar.SECOND, -1);
        service.setTspSource(getGoodTsaByTime(calendar.getTime()));
    }

    @Override
    protected DSSDocument sign() {
        numberOfCalls = 0;
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();
        assertEquals(1, numberOfCalls); // signCert CRL

        numberOfCalls = 0;
        documentToSign = signedDocument;
        signedDocument = super.sign();
        assertEquals(0, numberOfCalls);

        numberOfCalls = 0;
        documentToSign = signedDocument;
        signedDocument = super.sign();
        assertEquals(0, numberOfCalls);

        numberOfCalls = 0;
        documentToSign = signedDocument;
        signedDocument = super.sign();
        assertEquals(0, numberOfCalls);

        numberOfCalls = 0;
        documentToSign = signedDocument;
        signedDocument = super.sign();
        assertEquals(0, numberOfCalls);

        documentToSign = originalDocument;
        return signedDocument;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        // skip
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(5, diagnosticData.getAllSignatures().size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_WITH_CRL_AND_OCSP;
    }

    private class OnlineCRLSourceCounter extends OnlineCRLSource {

        private static final long serialVersionUID = 7677238056219199658L;

        @Override
        public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
            if (certificateToken.equals(getSigningCert())) {
                ++numberOfCalls;
            }
            return super.getRevocationToken(certificateToken, issuerCertificateToken);
        }

    }

}
