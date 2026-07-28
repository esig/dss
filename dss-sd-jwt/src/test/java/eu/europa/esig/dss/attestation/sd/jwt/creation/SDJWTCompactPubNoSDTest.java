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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonX509URLCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SDJWTCompactPubNoSDTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("Attestation provider");
        payloadParameters.nonSelectivelyDisclosable().setSubject(DSSASN1Utils.getSubjectCommonName(getSigningCert()));
        payloadParameters.setDeviceKey(getSigningCert().getPublicKey());

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.setStatusList(1, "https://pki.nowina.lu/eaa/status_list");
        payloadParameters.setCategory("urn:etsi:esi:eaa:eu:pub");

        payloadParameters.nonSelectivelyDisclosable().setGivenName("John");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("TEST Authority");
        payloadParameters.nonSelectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("VATLU-123456");

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        signatureParameters.setIncludeKeyIdentifier(false);
        signatureParameters.setX509Url("https://pki.nowina.lu/eaa/pub-attestation.crt");
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        CommonX509URLCertificateSource x509URLCertificateSource = new CommonX509URLCertificateSource();
        x509URLCertificateSource.addCertificate("https://pki.nowina.lu/eaa/pub-attestation.crt", getSigningCert());
        documentValidator.setSigningCertificateSource(x509URLCertificateSource);
        return documentValidator;
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
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper attestation = diagnosticData.getAttestationById(diagnosticData.getFirstAttestationId());
        assertEquals("urn:eudi:eaa:1", attestation.getVerifiableCredentialsTypeUri());
        assertEquals(DigestAlgorithm.SHA256, attestation.getVerifiableCredentialsTypeIntegrityDigestAlgorithm());
        assertArrayEquals(DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()), attestation.getVerifiableCredentialsTypeIntegrityBytes());
        assertEquals(DSSUtils.formatDateToRFC(getSignatureParameters().bLevel().getSigningDate()), DSSUtils.formatDateToRFC(attestation.getNotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(getSigningCert().getNotAfter()), DSSUtils.formatDateToRFC(attestation.getExpiration()));
        assertEquals("Attestation provider", attestation.getIssuer());
        assertEquals(DSSASN1Utils.getSubjectCommonName(getSigningCert()), attestation.getSubject());
        assertEquals("TEST Authority", attestation.getDocumentIssuingAuthority());
        assertEquals("LU", attestation.getDocumentIssuingAuthorityCountry());
        assertEquals("VATLU-123456", attestation.getIssuingRegistrationIdentifier());
        assertEquals("John", attestation.getGivenName());
        assertEquals("Doe", attestation.getFamilyName());

        assertEquals("urn:etsi:esi:eaa:eu:pub", attestation.getCategory());

        assertEquals(1, attestation.getStatusIndex());
        assertEquals("https://pki.nowina.lu/eaa/status_list", attestation.getStatusUri());

        assertArrayEquals(getSigningCert().getPublicKey().getEncoded(), attestation.getDevicePublicKey());
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}