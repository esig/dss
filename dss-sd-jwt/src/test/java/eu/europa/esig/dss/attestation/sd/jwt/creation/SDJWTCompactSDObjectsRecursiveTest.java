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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactSDObjectsRecursiveTest extends AbstractSDJWTTestIssuance {

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

        SDJWTClaimObject father = SDJWTClaim.createObject("father");
        father.addChild(SDJWTClaim.createSelectivelyDisclosable("given_name", "Ben"));
        father.addChild(SDJWTClaim.createSelectivelyDisclosable("family_name", "Doe"));
        SDJWTClaimArray nationalities = SDJWTClaim.createArraySelectivelyDisclosable("nationalities");
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("FR"));
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("LU"));
        father.addChild(nationalities);

        SDJWTClaimObject mother = SDJWTClaim.createObject("mother");
        mother.addChild(SDJWTClaim.createSelectivelyDisclosable("given_name", "Alice"));
        mother.addChild(SDJWTClaim.createSelectivelyDisclosable("family_name", "Doe Doeg"));
        nationalities = SDJWTClaim.createArraySelectivelyDisclosable("nationalities");
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("FR"));
        nationalities.addElement(SDJWTClaim.createSelectivelyDisclosable("DE"));
        mother.addChild(nationalities);

        payloadParameters.selectivelyDisclosable().addClaim(father);
        payloadParameters.selectivelyDisclosable().addClaim(mother);

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
        assertEquals(12, digestMatchers.size());

        boolean fatherSDFound = false;
        boolean fatherGivenNameSDFound = false;
        boolean fatherFamilyNameSDFound = false;
        boolean motherSDFound = false;
        boolean motherGivenNameSDFound = false;
        boolean motherFamilyNameSDFound = false;

        int nationalitiesSDFound = 0;
        int nationalitiesFRSDFound = 0;
        int nationalitiesLUSDFound = 0;
        int nationalitiesDESDFound = 0;

        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());
            if ("father".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                fatherSDFound = true;
            } else if ("Ben".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("given_name", xmlDigestMatcher.getDisclosableClaim().getName());
                fatherGivenNameSDFound = true;
            } else if ("Doe".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("family_name", xmlDigestMatcher.getDisclosableClaim().getName());
                fatherFamilyNameSDFound = true;
            } else if ("nationalities".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                ++nationalitiesSDFound;
            } else if ("FR".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertNull(xmlDigestMatcher.getDisclosableClaim().getName());
                ++nationalitiesFRSDFound;
            } else if ("LU".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertNull(xmlDigestMatcher.getDisclosableClaim().getName());
                ++nationalitiesLUSDFound;
            } else if ("DE".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertNull(xmlDigestMatcher.getDisclosableClaim().getName());
                ++nationalitiesDESDFound;
            } else if ("mother".equals(xmlDigestMatcher.getDisclosableClaim().getName())) {
                assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                motherSDFound = true;
            } else if ("Alice".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("given_name", xmlDigestMatcher.getDisclosableClaim().getName());
                motherGivenNameSDFound = true;
            } else if ("Doe Doeg".equals(xmlDigestMatcher.getDisclosableClaim().getValue())) {
                assertEquals("family_name", xmlDigestMatcher.getDisclosableClaim().getName());
                motherFamilyNameSDFound = true;
            }
        }
        assertTrue(fatherSDFound);
        assertTrue(fatherGivenNameSDFound);
        assertTrue(fatherFamilyNameSDFound);
        assertTrue(motherSDFound);
        assertTrue(motherGivenNameSDFound);
        assertTrue(motherFamilyNameSDFound);
        assertEquals(2, nationalitiesSDFound);
        assertEquals(2, nationalitiesFRSDFound);
        assertEquals(1, nationalitiesLUSDFound);
        assertEquals(1, nationalitiesDESDFound);
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