package eu.europa.esig.dss.attestation.sd.jwt.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationPayloadProxy;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactDuplicatedDisclosureValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/sd-jwt-compact-disclosure-duplicate.json");
    }

    @Override
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
        assertEquals(3, digestMatchers.size());

        boolean givenNameSDFound = false;
        boolean givenNameInvalidSDFound = false;
        boolean familyNameSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                if (xmlDigestMatcher.isDataIntact()) {
                    assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                    givenNameSDFound = true;
                } else {
                    assertEquals("Ben", xmlDigestMatcher.getDisclosableClaim().getValue());
                    givenNameInvalidSDFound = true;
                }
            } else if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            }
        }
        assertTrue(givenNameSDFound);
        assertTrue(givenNameInvalidSDFound);
        assertTrue(familyNameSDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestationWrapper = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        AttestationPayloadProxy eaaPayload = attestationWrapper.getPayload();
        assertEquals("John", eaaPayload.getGivenName().getText());
        assertEquals("Doe", eaaPayload.getFamilyName().getText());
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean sigFound = false;
        boolean kbSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertTrue(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());

                boolean jwsSDFound = false;
                boolean kbSDFound = false;
                for (XmlDigestMatcher xmlDigestMatcher : signatureWrapper.getDigestMatchers()) {
                    if (DigestMatcherType.JWS_SIGNING_INPUT == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertTrue(xmlDigestMatcher.isDataIntact());
                        jwsSDFound = true;
                    } else if (DigestMatcherType.EAA_KEY_BINDING == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        kbSDFound = true;
                    }
                }
                assertTrue(jwsSDFound);
                assertTrue(kbSDFound);
                kbSigFound = true;

            } else {
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());

                boolean jwsSDFound = false;
                for (XmlDigestMatcher xmlDigestMatcher : signatureWrapper.getDigestMatchers()) {
                    if (DigestMatcherType.JWS_SIGNING_INPUT == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertTrue(xmlDigestMatcher.isDataIntact());
                        jwsSDFound = true;
                    }
                }
                assertTrue(jwsSDFound);
                sigFound = true;

            }
        }
        assertTrue(sigFound);
        assertTrue(kbSigFound);
    }

}
