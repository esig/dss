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
import eu.europa.esig.dss.attestation.common.creation.TokenStatusList;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class SDJWTCompactStatusAndAttestedAttributesCreationTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        Date issuanceDate = new Date();

        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("https://issuer.example.com");
        payloadParameters.nonSelectivelyDisclosable().setIssuanceDate(issuanceDate);
        payloadParameters.setExpirationDate(new Date(issuanceDate.getTime() + 3600 * 1000));
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("Public body");
        payloadParameters.nonSelectivelyDisclosable().setGivenName("Alice");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.setVerifiableCredentialsType("https://nowina.lu/eaa/metadata");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "Hello World".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        SDJWTClaimObject status = SDJWTClaim.createObject("revocation");
        status.addChild(SDJWTClaim.create("type", "TokenStatusList"));
        status.addChild(SDJWTClaim.create("purpose", "revocation"));
        status.addChild(SDJWTClaim.create("index", 0));
        status.addChild(SDJWTClaim.create("uri", "https://nowina.lu/pki-factory/status"));
        payloadParameters.nonSelectivelyDisclosable().addClaim(status);

        payloadParameters.nonSelectivelyDisclosable().setAttestedAttributesSubjectIdentifier(
                DSSASN1Utils.getSubjectCommonName(getSigningCert()), Arrays.asList("given_name", "family_name")
        );

        payloadParameters.nonSelectivelyDisclosable().setPlaceOfBirthCountry("LU");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(issuanceDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setIncludeKeyIdentifier(false);
        signatureParameters.setSignatureType("dc+sd-jwt");
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
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);

        assertEquals("TokenStatusList", eaa.getStatusType());
        assertEquals("revocation", eaa.getStatusPurpose());
        assertEquals(0, eaa.getStatusIndex().intValue());
        assertEquals("https://nowina.lu/pki-factory/status", eaa.getStatusUri());

        assertEquals("good-user", eaa.getAttestedAttributesSubjectId());
        assertNull(eaa.getAttestedAttributesSubjectFamilyName());
        assertNull(eaa.getAttestedAttributesSubjectGivenName());
        assertNull(eaa.getAttestedAttributesSubjectDocumentNumber());
        assertNull(eaa.getAttestedAttributesSubjectPseudonym());
        assertEquals(Arrays.asList("given_name", "family_name"), eaa.getAttestedAttributes());

        assertEquals("LU", eaa.getPlaceOfBirthCountry());
    }

    @Override
    protected void assertStatusListEqual(TokenStatusList statusList, AttestationWrapper eaa) {
        // skip
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
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
