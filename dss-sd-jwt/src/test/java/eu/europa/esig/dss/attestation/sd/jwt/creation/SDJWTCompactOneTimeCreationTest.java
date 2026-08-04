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
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTCompactOneTimeCreationTest extends AbstractSDJWTTestCreation {

    private SDJWTPayloadParameters parameters;
    private JAdESSignatureParameters signatureParameters;

    private String signer;

    @BeforeEach
    void init() {
        signer = ECDSA_USER;

        parameters = new SDJWTPayloadParameters();
        parameters.setIssuer("https://issuer.example.com");
        parameters.nonSelectivelyDisclosable().setSubject(getSigningCert().getSubject().getPrettyPrintRFC2253());
        parameters.nonSelectivelyDisclosable().setIssuingAuthority("Public body");
        parameters.nonSelectivelyDisclosable().setIssuingCountry("LU");
        parameters.nonSelectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("XX12345");
        parameters.nonSelectivelyDisclosable().setGivenName("Alice");
        parameters.nonSelectivelyDisclosable().setFamilyName("Doe");

        parameters.setOneTime(true);

        parameters.setDeviceKey(getSigningCert().getPublicKey());

        signer = GOOD_USER;

        signatureParameters = new JAdESSignatureParameters();
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
        return parameters;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected void checkClaims(final DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestations().get(0);
        assertTrue(attestation.getOneTimeUse());
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return signer;
    }

}
