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
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SDJWTCompactWithDecoyDigestTest extends AbstractSDJWTTestCreation {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    private Date issuanceDate;
    private Date expiration;

    @BeforeEach
    void init() {
        issuanceDate = new Date();
        expiration = new Date(issuanceDate.getTime() + 3600 * 1000);

        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.nonSelectivelyDisclosable().setIssuanceDate(issuanceDate);
        payloadParameters.setExpirationDate(expiration);
        payloadParameters.setIssuer("https://issuer.example.com");

        payloadParameters.setDecoyDigestNumber(1);
        payloadParameters.selectivelyDisclosable().setGivenName("John");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        signatureParameters.setX509Url("http://nowina.lu/pki-factory/good-cert");
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
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        assertEquals("https://issuer.example.com", attestation.getIssuer());
        assertEquals(expiration.toInstant().getEpochSecond(), attestation.getExpiration().toInstant().getEpochSecond());
        assertEquals(issuanceDate.toInstant().getEpochSecond(), attestation.getIssuedAt().toInstant().getEpochSecond());

        List<ClaimWrapper> payloadClaims = attestation.getAllAttestationPayloadClaims();
        assertNotNull(payloadClaims);

        final List<XmlDigestMatcher> digestMatchers = attestation.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        int sdCounter = 0;
        int orphanCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            if (DigestMatcherType.SELECTIVE_DISCLOSURE == xmlDigestMatcher.getType()) {
                ++sdCounter;
            } else if (DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == xmlDigestMatcher.getType()) {
                ++orphanCounter;
            }
        }
        assertEquals(1, sdCounter);
        assertEquals(1, orphanCounter);

        // The auto generated one should be the same length as the length of the hash of the claim
        assertEquals(digestMatchers.get(0).getDigestValue().length, digestMatchers.get(1).getDigestValue().length);
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
