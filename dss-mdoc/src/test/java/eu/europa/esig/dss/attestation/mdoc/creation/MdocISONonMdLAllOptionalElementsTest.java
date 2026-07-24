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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class MdocISONonMdLAllOptionalElementsTest extends AbstractMdocPresentationTestIssuance {

    private MdocPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO23220_1_MID_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        payloadParameters.selectivelyDisclosable().setGivenName("John");
        payloadParameters.selectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setEmail("john.doe@example.com");
        payloadParameters.selectivelyDisclosable().setSex(1);
        payloadParameters.selectivelyDisclosable().setBirthdate(new Date(946684800000L)); // 2000-01-01
        payloadParameters.selectivelyDisclosable().setPhoneNumber("+352123456789");
        payloadParameters.selectivelyDisclosable().setPlaceOfBirthCountry("Luxembourg");
        payloadParameters.selectivelyDisclosable().setPlaceOfBirthLocality("Kehlen");
        payloadParameters.selectivelyDisclosable().setPlaceOfBirthRegion("Capellen");
        payloadParameters.selectivelyDisclosable().setNationality("LU");
        payloadParameters.selectivelyDisclosable().setBirthGivenName("Johnny");
        payloadParameters.selectivelyDisclosable().setBirthFamilyName("Doe");
        payloadParameters.selectivelyDisclosable().setTitle("Dr");
        payloadParameters.selectivelyDisclosable().setMobilePhoneNumber("+352987654321");
        payloadParameters.selectivelyDisclosable().setPseudonym("JD");
        payloadParameters.selectivelyDisclosable().setIssuingCountry("LU");
        payloadParameters.selectivelyDisclosable().setIssuingAuthority("Government of Luxembourg");
        payloadParameters.selectivelyDisclosable().setDocumentNumber("DOC123456");
        payloadParameters.selectivelyDisclosable().setPortrait(new byte[] {1, 2, 3});
        payloadParameters.selectivelyDisclosable().setDistinguishingSign("L");
        payloadParameters.selectivelyDisclosable().setPersonalAdministrativeNumber("ADM987654");
        payloadParameters.selectivelyDisclosable().setHeight(180);
        payloadParameters.selectivelyDisclosable().setWeight(75);
        payloadParameters.selectivelyDisclosable().setEyeColour("Brown");
        payloadParameters.selectivelyDisclosable().setHairColour("Black");
        payloadParameters.selectivelyDisclosable().setPostalAddress("1 Main Street");
        payloadParameters.selectivelyDisclosable().setPortraitCaptureDate(new Date(1704067200000L)); // 2024-01-01
        payloadParameters.selectivelyDisclosable().setAgeInYears(25);
        payloadParameters.selectivelyDisclosable().setAgeBirthYear(2000);
        payloadParameters.selectivelyDisclosable().setAgeOverNN(18 ,true);
        payloadParameters.selectivelyDisclosable().setAgeOverNN(21 ,true);
        payloadParameters.selectivelyDisclosable().setIssuingJurisdiction("LU-LU");
        payloadParameters.selectivelyDisclosable().setAddressCity("Luxembourg");
        payloadParameters.selectivelyDisclosable().setAddressState("Luxembourg");
        payloadParameters.selectivelyDisclosable().setAddressPostalCode("L-1234");
        payloadParameters.selectivelyDisclosable().setAddressCountry("LU");
        payloadParameters.selectivelyDisclosable().setBiometricTemplate("signature_sign", new byte[] {1, 2});
        payloadParameters.selectivelyDisclosable().setBiometricTemplateFace(new byte[] {4, 5, 6});
        payloadParameters.selectivelyDisclosable().setSignatureUsualMark(new byte[] {7, 8, 9});
        payloadParameters.selectivelyDisclosable().setFingerprint(new byte[] {10, 11, 12});
        payloadParameters.selectivelyDisclosable().setBusinessName("Doe Consulting");
        payloadParameters.selectivelyDisclosable().setOrganizationName("Doe Corporation");
        payloadParameters.selectivelyDisclosable().setBirthFullName("Johnny Doe");
        payloadParameters.selectivelyDisclosable().setProfession("Software Engineer");
        payloadParameters.selectivelyDisclosable().setRelationshipFather("Robert Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipMother("Jane Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipParent("Jane and Robert Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipSon("Michael Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipDaughter("Emily Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipBrother("David Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipSister("Sarah Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipSibling("David Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipSpouse("Anna Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipFatherInLaw("Peter Smith");
        payloadParameters.selectivelyDisclosable().setRelationshipMotherInLaw("Mary Smith");
        payloadParameters.selectivelyDisclosable().setRelationshipParentInLaw("Peter and Mary Smith");
        payloadParameters.selectivelyDisclosable().setRelationshipSonInLaw("James Brown");
        payloadParameters.selectivelyDisclosable().setRelationshipDaughterInLaw("Laura Brown");
        payloadParameters.selectivelyDisclosable().setRelationshipChildInLaw("Laura Brown");
        payloadParameters.selectivelyDisclosable().setRelationshipParentalAuthority("Anna Doe");
        payloadParameters.selectivelyDisclosable().setRelationshipLegalRepresentative("Law Firm SA");
        payloadParameters.selectivelyDisclosable().setRelationshipAgent("Agent Smith");
        payloadParameters.selectivelyDisclosable().setDocumentType("mDL");
        payloadParameters.selectivelyDisclosable().setAdministrativeIssuanceDate(new Date(1704067200000L));
        payloadParameters.selectivelyDisclosable().setAdministrativeExpirationDate(new Date(1735689600000L));
        payloadParameters.selectivelyDisclosable().setAddressStreet("Main Street");
        payloadParameters.selectivelyDisclosable().setAddressHouseNumber("1");
        payloadParameters.selectivelyDisclosable().setTrustAnchor("https://example.com/trust-anchor");
        payloadParameters.selectivelyDisclosable().setIssuingAuthorityRegistrationIdentifier("REG-123456");
        payloadParameters.selectivelyDisclosable().setAttestedAttributesSubjectPseudonym("X Man");

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected MdocPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAs().get(0);
        List<XmlDigestMatcher> digestMatchers = eaa.getDigestMatchers();
        assertEquals(68, digestMatchers.size());

        boolean givenNameFound = false;
        boolean familyNameFound = false;
        boolean emailFound = false;
        boolean genderFound = false;
        boolean birthdateFound = false;
        boolean phoneNumberFound = false;
        boolean placeOfBirthFound = false;
        boolean nationalityFound = false;
        boolean birthGivenNameFound = false;
        boolean birthFamilyNameFound = false;
        boolean titleFound = false;
        boolean mobilePhoneNumberFound = false;
        boolean pseudonymFound = false;
        boolean issuingCountryFound = false;
        boolean issuingAuthorityFound = false;
        boolean documentNumberFound = false;
        boolean portraitFound = false;
        boolean distinguishingSignFound = false;
        boolean administrativeNumberFound = false;
        boolean heightFound = false;
        boolean weightFound = false;
        boolean eyeColourFound = false;
        boolean hairColourFound = false;
        boolean postalAddressFound = false;
        boolean portraitCaptureDateFound = false;
        boolean ageInYearsFound = false;
        boolean ageBirthYearFound = false;
        boolean ageOver18Found = false;
        boolean ageOver21Found = false;
        boolean issuingJurisdictionFound = false;
        boolean residentAddressCityFound = false;
        boolean residentAddressStateFound = false;
        boolean residentAddressPostalCodeFound = false;
        boolean residentAddressCountryFound = false;
        boolean biometricTemplateSignatureSignFound = false;
        boolean biometricTemplateFaceFound = false;
        boolean signatureUsualMarkFound = false;
        boolean fingerprintFound = false;
        boolean businessNameFound = false;
        boolean organizationNameFound = false;
        boolean birthFullNameFound = false;
        boolean professionFound = false;
        boolean relationshipFatherFound = false;
        boolean relationshipMotherFound = false;
        boolean relationshipParentFound = false;
        boolean relationshipSonFound = false;
        boolean relationshipDaughterFound = false;
        boolean relationshipBrotherFound = false;
        boolean relationshipSisterFound = false;
        boolean relationshipSiblingFound = false;
        boolean relationshipSpouseFound = false;
        boolean relationshipFatherInLawFound = false;
        boolean relationshipMotherInLawFound = false;
        boolean relationshipParentInLawFound = false;
        boolean relationshipSonInLawFound = false;
        boolean relationshipDaughterInLawFound = false;
        boolean relationshipChildInLawFound = false;
        boolean relationshipParentalAuthorityFound = false;
        boolean relationshipLegalRepresentativeFound = false;
        boolean relationshipAgentFound = false;
        boolean documentTypeFound = false;
        boolean administrativeIssuanceDateFound = false;
        boolean administrativeExpirationDateFound = false;
        boolean residentAddressStreetFound = false;
        boolean residentAddressHouseNumberFound = false;
        boolean trustAnchorFound = false;
        boolean issuingAuthorityRegistrationIdentifierFound = false;
        boolean attestedAttributesPseudonymFound = false;

        for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
            assertNotNull(xmlDigestMatcher.getDisclosableClaim());

            String name = xmlDigestMatcher.getDisclosableClaim().getName();

            if ("given_name".equals(name)) {
                assertEquals("John", xmlDigestMatcher.getDisclosableClaim().getValue());
                givenNameFound = true;

            } else if ("family_name".equals(name)) {
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                familyNameFound = true;

            } else if ("email_address".equals(name)) {
                assertEquals("john.doe@example.com", xmlDigestMatcher.getDisclosableClaim().getValue());
                emailFound = true;

            } else if ("sex".equals(name)) {
                assertEquals("1", xmlDigestMatcher.getDisclosableClaim().getValue());
                genderFound = true;

            } else if ("birth_date".equals(name)) {
                assertEquals("{\"birth_date\": \"2000-01-01\"}", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthdateFound = true;

            } else if ("telephone_number".equals(name)) {
                assertEquals("+352123456789", xmlDigestMatcher.getDisclosableClaim().getValue());
                phoneNumberFound = true;

            } else if ("place_of_birth".equals(name)) {
                assertEquals("{\"country\": \"Luxembourg\", \"locality\": \"Kehlen\", \"region\": \"Capellen\"}", xmlDigestMatcher.getDisclosableClaim().getValue());
                placeOfBirthFound = true;

            } else if ("nationality".equals(name)) {
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                nationalityFound = true;

            } else if ("given_name_birth".equals(name)) {
                assertEquals("Johnny", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthGivenNameFound = true;

            } else if ("family_name_birth".equals(name)) {
                assertEquals("Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthFamilyNameFound = true;

            } else if ("title".equals(name)) {
                assertEquals("Dr", xmlDigestMatcher.getDisclosableClaim().getValue());
                titleFound = true;

            } else if ("mobile_phone_number".equals(name)) {
                assertEquals("+352987654321", xmlDigestMatcher.getDisclosableClaim().getValue());
                mobilePhoneNumberFound = true;

            } else if ("also_known_as".equals(name)) {
                assertEquals("JD", xmlDigestMatcher.getDisclosableClaim().getValue());
                pseudonymFound = true;

            } else if ("issuing_country".equals(name)) {
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingCountryFound = true;

            } else if ("issuing_authority".equals(name)) {
                assertEquals("Government of Luxembourg", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthorityFound = true;

            } else if ("document_number".equals(name)) {
                assertEquals("DOC123456", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentNumberFound = true;

            } else if ("portrait".equals(name)) {
                assertEquals("AQID", xmlDigestMatcher.getDisclosableClaim().getValue());
                portraitFound = true;

            } else if ("un_distinguishing_sign".equals(name)) {
                assertEquals("L", xmlDigestMatcher.getDisclosableClaim().getValue());
                distinguishingSignFound = true;

            } else if ("administrative_number".equals(name)) {
                assertEquals("ADM987654", xmlDigestMatcher.getDisclosableClaim().getValue());
                administrativeNumberFound = true;

            } else if ("height".equals(name)) {
                assertEquals("180", xmlDigestMatcher.getDisclosableClaim().getValue());
                heightFound = true;

            } else if ("weight".equals(name)) {
                assertEquals("75", xmlDigestMatcher.getDisclosableClaim().getValue());
                weightFound = true;

            } else if ("eye_colour".equals(name)) {
                assertEquals("Brown", xmlDigestMatcher.getDisclosableClaim().getValue());
                eyeColourFound = true;

            } else if ("hair_colour".equals(name)) {
                assertEquals("Black", xmlDigestMatcher.getDisclosableClaim().getValue());
                hairColourFound = true;

            } else if ("resident_address".equals(name)) {
                assertEquals("1 Main Street", xmlDigestMatcher.getDisclosableClaim().getValue());
                postalAddressFound = true;

            } else if ("portrait_capture_date".equals(name)) {
                assertEquals("2024-01-01T00:00:00Z", xmlDigestMatcher.getDisclosableClaim().getValue());
                portraitCaptureDateFound = true;

            } else if ("age_in_years".equals(name)) {
                assertEquals("25", xmlDigestMatcher.getDisclosableClaim().getValue());
                ageInYearsFound = true;

            } else if ("age_birth_year".equals(name)) {
                assertEquals("2000", xmlDigestMatcher.getDisclosableClaim().getValue());
                ageBirthYearFound = true;

            } else if ("age_over_18".equals(name)) {
                assertEquals("true", xmlDigestMatcher.getDisclosableClaim().getValue());
                ageOver18Found = true;

            } else if ("age_over_21".equals(name)) {
                assertEquals("true", xmlDigestMatcher.getDisclosableClaim().getValue());
                ageOver21Found = true;

            } else if ("issuing_subdivision".equals(name)) {
                assertEquals("LU-LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingJurisdictionFound = true;

            } else if ("resident_city".equals(name)) {
                assertEquals("Luxembourg", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressCityFound = true;

            } else if ("resident_state".equals(name)) {
                assertEquals("Luxembourg", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressStateFound = true;

            } else if ("resident_postal_code".equals(name)) {
                assertEquals("L-1234", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressPostalCodeFound = true;

            } else if ("resident_country".equals(name)) {
                assertEquals("LU", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressCountryFound = true;

            } else if ("biometric_template_signature_sign".equals(name)) {
                assertEquals("AQI=", xmlDigestMatcher.getDisclosableClaim().getValue());
                biometricTemplateSignatureSignFound = true;

            } else if ("biometric_template_face".equals(name)) {
                assertEquals("BAUG", xmlDigestMatcher.getDisclosableClaim().getValue());
                biometricTemplateFaceFound = true;

            } else if ("signature_usual_mark".equals(name)) {
                assertEquals("BwgJ", xmlDigestMatcher.getDisclosableClaim().getValue());
                signatureUsualMarkFound = true;

            } else if ("fingerprint".equals(name)) {
                assertEquals("CgsM", xmlDigestMatcher.getDisclosableClaim().getValue());
                fingerprintFound = true;

            } else if ("business_name".equals(name)) {
                assertEquals("Doe Consulting", xmlDigestMatcher.getDisclosableClaim().getValue());
                businessNameFound = true;

            } else if ("organization_name".equals(name)) {
                assertEquals("Doe Corporation", xmlDigestMatcher.getDisclosableClaim().getValue());
                organizationNameFound = true;

            } else if ("name_at_birth".equals(name)) {
                assertEquals("Johnny Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                birthFullNameFound = true;

            } else if ("profession".equals(name)) {
                assertEquals("Software Engineer", xmlDigestMatcher.getDisclosableClaim().getValue());
                professionFound = true;

            } else if ("father".equals(name)) {
                assertEquals("Robert Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipFatherFound = true;

            } else if ("mother".equals(name)) {
                assertEquals("Jane Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipMotherFound = true;

            } else if ("parent".equals(name)) {
                assertEquals("Jane and Robert Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipParentFound = true;

            } else if ("son".equals(name)) {
                assertEquals("Michael Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipSonFound = true;

            } else if ("daughter".equals(name)) {
                assertEquals("Emily Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipDaughterFound = true;

            } else if ("brother".equals(name)) {
                assertEquals("David Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipBrotherFound = true;

            } else if ("sister".equals(name)) {
                assertEquals("Sarah Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipSisterFound = true;

            } else if ("sibling".equals(name)) {
                assertEquals("David Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipSiblingFound = true;

            } else if ("spouse".equals(name)) {
                assertEquals("Anna Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipSpouseFound = true;

            } else if ("father_in_law".equals(name)) {
                assertEquals("Peter Smith", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipFatherInLawFound = true;

            } else if ("mother_in_law".equals(name)) {
                assertEquals("Mary Smith", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipMotherInLawFound = true;

            } else if ("parent_in_law".equals(name)) {
                assertEquals("Peter and Mary Smith", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipParentInLawFound = true;

            } else if ("son_in_law".equals(name)) {
                assertEquals("James Brown", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipSonInLawFound = true;

            } else if ("daughter_in_law".equals(name)) {
                assertEquals("Laura Brown", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipDaughterInLawFound = true;

            } else if ("child_in_law".equals(name)) {
                assertEquals("Laura Brown", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipChildInLawFound = true;

            } else if ("parental_authority".equals(name)) {
                assertEquals("Anna Doe", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipParentalAuthorityFound = true;

            } else if ("legal_representative".equals(name)) {
                assertEquals("Law Firm SA", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipLegalRepresentativeFound = true;

            } else if ("agent".equals(name)) {
                assertEquals("Agent Smith", xmlDigestMatcher.getDisclosableClaim().getValue());
                relationshipAgentFound = true;

            } else if ("document_type".equals(name)) {
                assertEquals("mDL", xmlDigestMatcher.getDisclosableClaim().getValue());
                documentTypeFound = true;

            } else if ("issue_date".equals(name)) {
                assertEquals("2024-01-01", xmlDigestMatcher.getDisclosableClaim().getValue());
                administrativeIssuanceDateFound = true;

            } else if ("expiry_date".equals(name)) {
                assertEquals("2025-01-01", xmlDigestMatcher.getDisclosableClaim().getValue());
                administrativeExpirationDateFound = true;

            } else if ("resident_street".equals(name)) {
                assertEquals("Main Street", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressStreetFound = true;

            } else if ("resident_house_number".equals(name)) {
                assertEquals("1", xmlDigestMatcher.getDisclosableClaim().getValue());
                residentAddressHouseNumberFound = true;

            } else if ("trust_anchor".equals(name)) {
                assertEquals("https://example.com/trust-anchor", xmlDigestMatcher.getDisclosableClaim().getValue());
                trustAnchorFound = true;

            } else if ("iss_reg_id".equals(name)) {
                assertEquals("REG-123456", xmlDigestMatcher.getDisclosableClaim().getValue());
                issuingAuthorityRegistrationIdentifierFound = true;

            } else if ("SubAttr".equals(name)) {
                assertEquals("{\"subAka\": \"X Man\"}", xmlDigestMatcher.getDisclosableClaim().getValue());
                attestedAttributesPseudonymFound = true;

            } else {
                fail(String.format("Unexpected claim : '%s'", xmlDigestMatcher.getDisclosableClaim().getName()));
            }
        }

        assertTrue(givenNameFound);
        assertTrue(familyNameFound);
        assertTrue(emailFound);
        assertTrue(genderFound);
        assertTrue(birthdateFound);
        assertTrue(phoneNumberFound);
        assertTrue(placeOfBirthFound);
        assertTrue(nationalityFound);
        assertTrue(birthGivenNameFound);
        assertTrue(birthFamilyNameFound);
        assertTrue(titleFound);
        assertTrue(mobilePhoneNumberFound);
        assertTrue(pseudonymFound);
        assertTrue(issuingCountryFound);
        assertTrue(issuingAuthorityFound);
        assertTrue(documentNumberFound);
        assertTrue(portraitFound);
        assertTrue(distinguishingSignFound);
        assertTrue(administrativeNumberFound);
        assertTrue(heightFound);
        assertTrue(weightFound);
        assertTrue(eyeColourFound);
        assertTrue(hairColourFound);
        assertTrue(postalAddressFound);
        assertTrue(portraitCaptureDateFound);
        assertTrue(ageInYearsFound);
        assertTrue(ageBirthYearFound);
        assertTrue(ageOver18Found);
        assertTrue(ageOver21Found);
        assertTrue(issuingJurisdictionFound);
        assertTrue(residentAddressCityFound);
        assertTrue(residentAddressStateFound);
        assertTrue(residentAddressPostalCodeFound);
        assertTrue(residentAddressCountryFound);
        assertTrue(biometricTemplateSignatureSignFound);
        assertTrue(biometricTemplateFaceFound);
        assertTrue(signatureUsualMarkFound);
        assertTrue(fingerprintFound);
        assertTrue(businessNameFound);
        assertTrue(organizationNameFound);
        assertTrue(birthFullNameFound);
        assertTrue(professionFound);
        assertTrue(relationshipFatherFound);
        assertTrue(relationshipMotherFound);
        assertTrue(relationshipParentFound);
        assertTrue(relationshipSonFound);
        assertTrue(relationshipDaughterFound);
        assertTrue(relationshipBrotherFound);
        assertTrue(relationshipSisterFound);
        assertTrue(relationshipSiblingFound);
        assertTrue(relationshipSpouseFound);
        assertTrue(relationshipFatherInLawFound);
        assertTrue(relationshipMotherInLawFound);
        assertTrue(relationshipParentInLawFound);
        assertTrue(relationshipSonInLawFound);
        assertTrue(relationshipDaughterInLawFound);
        assertTrue(relationshipChildInLawFound);
        assertTrue(relationshipParentalAuthorityFound);
        assertTrue(relationshipLegalRepresentativeFound);
        assertTrue(relationshipAgentFound);
        assertTrue(documentTypeFound);
        assertTrue(administrativeIssuanceDateFound);
        assertTrue(administrativeExpirationDateFound);
        assertTrue(residentAddressStreetFound);
        assertTrue(residentAddressHouseNumberFound);
        assertTrue(trustAnchorFound);
        assertTrue(issuingAuthorityRegistrationIdentifierFound);
        assertTrue(attestedAttributesPseudonymFound);
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertEquals("1.0", eaa.getVersion());
        assertEquals("org.iso.23220.1.mID", eaa.getAttestationDocumentType());
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}
