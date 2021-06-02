package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CMSSignatureWithoutCertificatesTest extends AbstractCAdESTestSignature {

    private DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> service;
    private CAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello world!".getBytes());

        signatureParameters = new CAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setGenerateTBSWithoutCertificate(true);

        service = new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CommonCertificateSource signingCertificateSource = new CommonCertificateSource();
        signingCertificateSource.addCertificate(getSigningCert());
        validator.setSigningCertificateSource(signingCertificateSource);

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
        for (CertificateToken certificateToken : getCertificateChain()) {
            adjunctCertificateSource.addCertificate(certificateToken);
        }
        certificateVerifier.addAdjunctCertSources(adjunctCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId()));
        assertEquals(3, diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId()).size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CMS_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
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
        return GOOD_USER;
    }

}
