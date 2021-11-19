package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelBEnvelopingNoKidTest extends AbstractJAdESTestSignature {

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private DSSDocument documentToSign;

    private Date signingDate;

    @BeforeEach
    public void init() throws Exception {
        service = new JAdESService(getOfflineCertificateVerifier());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signingDate = new Date();
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setIncludeKeyIdentifier(false);
        return signatureParameters;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> signCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(1, signCerts.size());

        List<CertificateRefWrapper> signCertReferences = signCerts.get(0).getReferences();
        assertEquals(1, signCertReferences.size());

        boolean signCertRefFound = false;
        boolean kidCertRefFound = false;
        for (CertificateRefWrapper certificateRefWrapper : signCertReferences) {
            if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRefWrapper.getOrigin())) {
                signCertRefFound = true;
            } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRefWrapper.getOrigin())) {
                kidCertRefFound = true;
            }
        }
        assertTrue(signCertRefFound);
        assertFalse(kidCertRefFound);

        assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
        assertEquals(0, foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
