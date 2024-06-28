package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBNoKeyInfoSignCertTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-no-keyinfo-sign-cert.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BES, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
        assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());

        CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertFalse(signingCertificateReference.isDigestValueMatch());
        assertTrue(signingCertificateReference.isIssuerSerialPresent());
        assertFalse(signingCertificateReference.isIssuerSerialMatch());

        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNull(signingCertificate);
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        assertNull(signerInformation);
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects()));
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanCertificateReferences()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
        assertEquals(0, Utils.collectionSize(diagnosticData.getAllOrphanRevocationReferences()));
    }

}
