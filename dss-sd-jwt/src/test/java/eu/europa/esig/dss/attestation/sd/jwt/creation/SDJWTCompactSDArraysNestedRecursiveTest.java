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
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactSDArraysNestedRecursiveTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("EAA provider");
        payloadParameters.nonSelectivelyDisclosable().setSubject(DSSASN1Utils.getSubjectCommonName(getSigningCert()));
        payloadParameters.setDeviceKey(getSigningCert().getPublicKey());

        payloadParameters.setVerifiableCredentialsType("urn:eudi:attestation:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        SDJWTClaimArray pets = SDJWTClaim.createArray("pets");
        SDJWTClaimObject bella = SDJWTClaim.createObjectSelectivelyDisclosable();
        bella.addChild(SDJWTClaim.createSelectivelyDisclosable("name", "Bella"));
        bella.addChild(SDJWTClaim.createSelectivelyDisclosable("type", "dog"));
        pets.addElement(bella);
        SDJWTClaimObject slinky = SDJWTClaim.createObjectSelectivelyDisclosable();
        slinky.addChild(SDJWTClaim.createSelectivelyDisclosable("name", "Slinky"));
        slinky.addChild(SDJWTClaim.createSelectivelyDisclosable("type", "cat"));
        pets.addElement(slinky);
        payloadParameters.selectivelyDisclosable().addClaim(pets);

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
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
        assertEquals(7, digestMatchers.size());

        boolean petsSDFound = false;
        boolean bellaSDFound = false;
        boolean slinkySDFound = false;
        boolean dogSDFound = false;
        boolean catSDFound = false;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("pets".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                petsSDFound = true;
            } else if ("Bella".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("name", xmlDigestMatcher.getDisclosableClaim().getName());
                bellaSDFound = true;
            } else if ("Slinky".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("name", xmlDigestMatcher.getDisclosableClaim().getName());
                slinkySDFound = true;
            } else if ("dog".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("type", xmlDigestMatcher.getDisclosableClaim().getName());
                dogSDFound = true;
            } else if ("cat".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("type", xmlDigestMatcher.getDisclosableClaim().getName());
                catSDFound = true;
            }
        }
        assertTrue(petsSDFound);
        assertTrue(bellaSDFound);
        assertTrue(slinkySDFound);
        assertTrue(dogSDFound);
        assertTrue(catSDFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<ClaimWrapper> otherClaims = eaa.getOtherClaims();
        assertEquals(1, otherClaims.size());

        ClaimWrapper pets = otherClaims.get(0);
        assertEquals("pets", pets.getName());
        assertEquals(2, pets.getList().size());

        boolean bellaFound = false;
        boolean slinkyFound = false;
        for (ClaimWrapper pet : pets.getList()) {
            assertNull(pet.getName());

            Map<String, ClaimWrapper> petObject = pet.getMap();
            assertEquals(2, petObject.size());
            if ("Bella".equals(petObject.get("name").getText())) {
                assertEquals("dog", petObject.get("type").getText());
                bellaFound = true;
            } else if ("Slinky".equals(petObject.get("name").getText())) {
                assertEquals("cat", petObject.get("type").getText());
                slinkyFound = true;
            }
        }
        assertTrue(bellaFound);
        assertTrue(slinkyFound);
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