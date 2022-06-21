package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.RevocationDataVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelLTWithSHA1OcspResponseTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private CertificateVerifier certificateVerifier;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new FileDocument(new File("src/test/resources/sample.xml"));

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        certificateVerifier = getCompleteCertificateVerifier();
        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA1);
        certificateVerifier.setOcspSource(ocspSource);

        service = new XAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        Exception exception = assertThrows(AlertException.class, () -> super.sign());
        assertTrue(exception.getMessage().contains("Revocation data is missing for one or more certificate(s)."));

        // accept SHA-1
        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setAcceptableDigestAlgorithms(Arrays.asList(
                DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA512));
        certificateVerifier.setRevocationDataVerifier(revocationDataVerifier);

        return super.sign();
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);

        // Ensure SHA-1 revocation is being rejected and a new one is requested
        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();
        RevocationDataVerifier revocationDataVerifier = RevocationDataVerifier.createDefaultRevocationDataVerifier();
        revocationDataVerifier.setAcceptableDigestAlgorithms(Arrays.asList(
                DigestAlgorithm.SHA256, DigestAlgorithm.SHA512));
        certificateVerifier.setRevocationDataVerifier(revocationDataVerifier);

        OnlineOCSPSource ocspSource = new OnlineOCSPSource();
        ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA256);
        certificateVerifier.setOcspSource(ocspSource);

        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertNotNull(signingCertificate);

        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(2, certificateRevocationData.size());

        boolean sha1OcspFound = false;
        boolean sha256OcspFound = false;
        for (RevocationWrapper revocationWrapper : certificateRevocationData) {
            if (DigestAlgorithm.SHA1.equals(revocationWrapper.getDigestAlgorithm())) {
                assertEquals(RevocationOrigin.INPUT_DOCUMENT, revocationWrapper.getOrigin());
                sha1OcspFound = true;
            } else if (DigestAlgorithm.SHA256.equals(revocationWrapper.getDigestAlgorithm())) {
                assertEquals(RevocationOrigin.EXTERNAL, revocationWrapper.getOrigin());
                sha256OcspFound = true;
            }
        }
        assertTrue(sha1OcspFound);
        assertTrue(sha256OcspFound);
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
        return GOOD_USER_WITH_OCSP_CERT_ID_DIGEST;
    }

}