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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactSDArraysAndObjectsNonRecursiveTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("Attestation provider");
        payloadParameters.nonSelectivelyDisclosable().setSubject(DSSASN1Utils.getSubjectCommonName(getSigningCert()));
        payloadParameters.setDeviceKey(getSigningCert().getPublicKey());

        payloadParameters.setVerifiableCredentialsType("urn:eudi:attestation:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.selectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("VATLU-123456");

        SDJWTClaimArray nationalities = SDJWTClaim.createArray("pets");
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("dog"));
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("cat"));
        payloadParameters.nonSelectivelyDisclosable().addClaim(nationalities);

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected SDJWTPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected SDJWTKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected void checkAttestationDigestMatchers(DiagnosticData diagnosticData) {
        super.checkAttestationDigestMatchers(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(7, digestMatchers.size());

        boolean familyNameSDFound = false;
        boolean givenNameSDFound = false;
        boolean issuingCountrySDFound = false;
        boolean issuingAuthoritySDFound = false;
        boolean issuingAuthorityRegNumberSDFound = false;
        boolean petsSDFound = false;
        boolean dogSDFound = false;
        boolean catSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("family_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameSDFound = true;
            } else if ("given_name".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameSDFound = true;
            } else if ("issuing_country".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingCountrySDFound = true;
            } else if ("issuing_authority".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("TEST Authority", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthoritySDFound = true;
            } else if ("iss_reg_id".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertEquals("VATLU-123456", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthorityRegNumberSDFound = true;
            } else if ("pets".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                petsSDFound = true;
            } else if ("dog".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertNull(xmlDigestMatcher.getDisclosableClaim().getName());
                dogSDFound = true;
            } else if ("cat".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertNull(xmlDigestMatcher.getDisclosableClaim().getName());
                catSDFound = true;
            }
        }
        assertTrue(familyNameSDFound);
        assertTrue(givenNameSDFound);
        assertTrue(issuingCountrySDFound);
        assertTrue(issuingAuthoritySDFound);
        assertTrue(issuingAuthorityRegNumberSDFound);
        assertFalse(petsSDFound);
        assertTrue(dogSDFound);
        assertTrue(catSDFound);
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}