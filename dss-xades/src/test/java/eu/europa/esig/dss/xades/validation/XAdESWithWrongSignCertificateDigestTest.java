package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithWrongSignCertificateDigestTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-wrong-sign-cert-digest.xml");
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);

        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> signingCertRefs = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(1, signingCertRefs.size());

        RelatedCertificateWrapper signingCertificate = signingCertRefs.get(0);
        assertEquals(1, signingCertificate.getReferences().size());

        CertificateRefWrapper signingCertificateRef = signingCertificate.getReferences().get(0);
        assertNotNull(signingCertificateRef.getDigestAlgoAndValue());
        assertTrue(signingCertificateRef.isDigestValuePresent());
        assertFalse(signingCertificateRef.isDigestValueMatch());
        assertNotNull(signingCertificateRef.getIssuerSerial());
        assertTrue(signingCertificateRef.isIssuerSerialPresent());
        assertTrue(signingCertificateRef.isIssuerSerialMatch());

        List<OrphanCertificateWrapper> orphanSigningCertificates = foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(0, orphanSigningCertificates.size());
    }

}
