package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBWithSignCertV2WrongIssuerSerialTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-sign-cert-v2-wrong-issuer-serial.xml");
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertTrue(signingCertificateReference.isDigestValueMatch());
        assertFalse(signingCertificateReference.isIssuerSerialPresent());
        assertFalse(signingCertificateReference.isIssuerSerialMatch());
        assertNull(signingCertificateReference.getIssuerSerial());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signatureWrapper.isStructuralValidationValid());

        boolean containsInvalidIssuerSerial = false;
        for (String message : signatureWrapper.getStructuralValidationMessages()) {
            if (message.contains("The value '...' of element 'xades:IssuerSerialV2' is not valid")) {
                containsInvalidIssuerSerial = true;
            }
        }
        assertTrue(containsInvalidIssuerSerial);
    }

}
