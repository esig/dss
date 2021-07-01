package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DSS2506Test extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss-2506.xml");
    }

    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // orphan data must not be added into the signature
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        assertFalse(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateReferences())); // orphan signing cert
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().iterator().next();
        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        assertTrue(Utils.isCollectionNotEmpty(digestMatchers));

        assertFalse(signatureWrapper.isSignatureIntact());
        assertFalse(signatureWrapper.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
    }

    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatures().iterator().next();
        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
        assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());

        assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates().getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

        List<CertificateRefWrapper> orphanSigningCertificates = signatureWrapper.foundCertificates().getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertTrue(Utils.isCollectionNotEmpty(orphanSigningCertificates));
        assertEquals(1, orphanSigningCertificates.size());

        CertificateRefWrapper orphan = orphanSigningCertificates.iterator().next();
        assertNotNull(orphan.getDigestAlgoAndValue());
        assertTrue(orphan.isIssuerSerialPresent());
        assertFalse(orphan.isIssuerSerialMatch());
    }

    protected void validateSignerInformation(SignerInformationType signerInformation) {
        assertNull(signerInformation);
    }

}
