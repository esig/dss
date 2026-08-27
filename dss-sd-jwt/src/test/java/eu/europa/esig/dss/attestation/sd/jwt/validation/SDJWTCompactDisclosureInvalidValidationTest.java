/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactDisclosureInvalidValidationTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/sd-jwt-compact-disclosure-invalid.json");
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean givenNameSDFound = false;
        boolean familyNameSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertTrue(xmlDigestMatcher.isDataFound());
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertFalse(xmlDigestMatcher.isDataIntact());
                assertEquals("Ben", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameSDFound = true;
            } else if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertTrue(xmlDigestMatcher.isDataIntact());
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            }
        }
        assertTrue(givenNameSDFound);
        assertTrue(familyNameSDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestationWrapper = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        AttestationPayloadProxy attestationPayload = attestationWrapper.getPayload();
        assertNull(attestationPayload.getGivenName());
        assertEquals("Doe", attestationPayload.getFamilyName().getText());
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
                    } else if (DigestMatcherType.KEY_BINDING_SIGNATURE == xmlDigestMatcher.getType()) {
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
