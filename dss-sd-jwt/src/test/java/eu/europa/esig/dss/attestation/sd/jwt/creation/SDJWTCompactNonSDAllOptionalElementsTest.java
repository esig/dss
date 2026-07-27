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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.CommonX509URLCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

class SDJWTCompactNonSDAllOptionalElementsTest extends AbstractSDJWTTestIssuance {

    private SDJWTPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTPayloadParameters();
        payloadParameters.setIssuer("Attestation provider");
        payloadParameters.nonSelectivelyDisclosable().setSubject(DSSASN1Utils.getSubjectCommonName(getSigningCert()));
        payloadParameters.setDeviceKey(getSigningCert().getPublicKey());

        payloadParameters.nonSelectivelyDisclosable().setGivenName("John");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setBirthdate(new Date(946684800000L)); // 2000-01-01
        payloadParameters.nonSelectivelyDisclosable().setNationalities(Collections.singletonList("LUX"));
        payloadParameters.nonSelectivelyDisclosable().setEmail("john.doe@example.com");
        payloadParameters.nonSelectivelyDisclosable().setPhoneNumber("+352123456789");

        payloadParameters.nonSelectivelyDisclosable().setPostalAddress("1 Main Street");
        payloadParameters.nonSelectivelyDisclosable().setAddressHouseNumber("1");
        payloadParameters.nonSelectivelyDisclosable().setAddressStreet("Main Street");
        payloadParameters.nonSelectivelyDisclosable().setAddressCity("Kehlen");
        payloadParameters.nonSelectivelyDisclosable().setAddressState("Capellen");
        payloadParameters.nonSelectivelyDisclosable().setAddressPostalCode("L-1234");
        payloadParameters.nonSelectivelyDisclosable().setAddressCountry("LU");

        payloadParameters.nonSelectivelyDisclosable().setPlaceOfBirthCountry("LU");
        payloadParameters.nonSelectivelyDisclosable().setPlaceOfBirthRegion("Luxembourg");
        payloadParameters.nonSelectivelyDisclosable().setPlaceOfBirthLocality("Luxembourg City");

        payloadParameters.nonSelectivelyDisclosable().setBirthGivenName("Johnny");
        payloadParameters.nonSelectivelyDisclosable().setBirthFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setTitle("Dr");
        payloadParameters.nonSelectivelyDisclosable().setMobilePhoneNumber("+352987654321");
        payloadParameters.nonSelectivelyDisclosable().setPseudonym("JD");

        payloadParameters.nonSelectivelyDisclosable().setPersonalAdministrativeNumber("ADM987654");

        payloadParameters.nonSelectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("Government of Luxembourg");
        payloadParameters.nonSelectivelyDisclosable().setIssuingJurisdiction("LU-LU");
        payloadParameters.nonSelectivelyDisclosable().setDocumentNumber("DOC123456");

        payloadParameters.nonSelectivelyDisclosable().setAgeInYears(25);
        payloadParameters.nonSelectivelyDisclosable().setAgeBirthYear(2000);
        payloadParameters.nonSelectivelyDisclosable().setAgeOverNN(18, true);
        payloadParameters.nonSelectivelyDisclosable().setAgeOverNN(21, false);

        payloadParameters.nonSelectivelyDisclosable().setTrustAnchor("https://example.com/trust-anchor");

        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("REG-123456");

        payloadParameters.nonSelectivelyDisclosable().setAttestedAttributesSubjectIdentifier("SUBJ-123456", Arrays.asList("given_name", "family_name"));

        payloadParameters.nonSelectivelyDisclosable().setPicture("https://example.com/john.jpg");
        payloadParameters.nonSelectivelyDisclosable().setNickname("johnny");
        payloadParameters.nonSelectivelyDisclosable().setPreferredNickname("jd");
        payloadParameters.nonSelectivelyDisclosable().setName("Dr. John Doe");
        payloadParameters.nonSelectivelyDisclosable().setMiddleName("William");

        payloadParameters.nonSelectivelyDisclosable().setProfile("https://example.com/profile/john");
        payloadParameters.nonSelectivelyDisclosable().setWebsite("https://johndoe.example");

        payloadParameters.nonSelectivelyDisclosable().setEmailVerified(Boolean.TRUE);
        payloadParameters.nonSelectivelyDisclosable().setSex(1);

        payloadParameters.nonSelectivelyDisclosable().setZoneinfo("Europe/Luxembourg");
        payloadParameters.nonSelectivelyDisclosable().setLocale("en-LU");

        payloadParameters.nonSelectivelyDisclosable().setPhoneNumberVerified(Boolean.TRUE);

        payloadParameters.nonSelectivelyDisclosable().setUpdatedAt(new Date(1711929600000L)); // 2024-04-01

        payloadParameters.nonSelectivelyDisclosable().setBirthMiddleName("William");

        payloadParameters.nonSelectivelyDisclosable().setSalutation("Mr.");

        payloadParameters.nonSelectivelyDisclosable().setAdministrativeIssuanceDate(new Date(1704067200000L)); // 2024-01-01
        payloadParameters.nonSelectivelyDisclosable().setAdministrativeExpirationDate(new Date(1735689600000L));   // 2025-01-01

        SDJWTClaimObject employment = SDJWTClaim.createObject("employment");

        employment.addChild(SDJWTClaim.create("company", "OpenAI"));
        employment.addChild(SDJWTClaim.create("role", "Engineer"));

        SDJWTClaimArray skills = SDJWTClaim.createArray("skills");
        skills.addElement(SDJWTClaim.create("Java"));
        skills.addElement(SDJWTClaim.create("OAuth"));
        skills.addElement(SDJWTClaim.create("SD-JWT"));

        employment.addChild(skills);

        payloadParameters.nonSelectivelyDisclosable().getOtherClaims().add(employment);

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