package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactWithJwkWithX5cTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sd-jwt-jwk-with-x5c.json"));
    }

    @Override
    protected void checkDeviceKeyClaim(DiagnosticData diagnosticData) {
        super.checkDeviceKeyClaim(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertNotNull(attestation.getDevicePublicKey());
        assertNotNull(attestation.getDeviceCertificate());
        assertTrue(Utils.isCollectionNotEmpty(attestation.getDeviceCertificateChain()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        boolean attestationSignatureFound = false;
        boolean kbSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNull(signatureWrapper.getSigningCertificatePublicKey());
            assertNotNull(signatureWrapper.getSigningCertificate());
            if (signatureWrapper.isKeyBindingSignature()) {
                kbSignatureFound = true;
            } else {
                attestationSignatureFound = true;
            }
        }
        assertTrue(attestationSignatureFound);
        assertTrue(kbSignatureFound);
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

}