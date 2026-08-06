package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactWithJwkWithX5cOnlyTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sd-jwt-jwk-x5c-only.json"));
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean attestationSignatureFound = false;
        boolean kbSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                boolean jwsInputFound = false;
                boolean kbInputFound = false;
                for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
                    if (DigestMatcherType.JWS_SIGNING_INPUT == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        jwsInputFound = true;
                    } else if (DigestMatcherType.KEY_BINDING_SIGNATURE == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        kbInputFound = true;
                    }
                }
                assertTrue(jwsInputFound);
                assertTrue(kbInputFound);
                kbSignatureFound = true;

            } else {
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                for (XmlDigestMatcher digestMatcher : signatureWrapper.getDigestMatchers()) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                }
                attestationSignatureFound = true;
            }
        }
        assertTrue(attestationSignatureFound);
        assertTrue(kbSignatureFound);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        boolean attestationSignatureFound = false;
        boolean kbSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertNull(signatureWrapper.getSigningCertificatePublicKey());
                assertNull(signatureWrapper.getSigningCertificate());
                kbSignatureFound = true;

            } else {
                assertNotNull(signatureWrapper.getSigningCertificate());
                attestationSignatureFound = true;
            }
        }
        assertTrue(attestationSignatureFound);
        assertTrue(kbSignatureFound);
    }

    @Override
    protected void checkDeviceKeyClaim(DiagnosticData diagnosticData) {
        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertNull(attestation.getDevicePublicKey());
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

}
