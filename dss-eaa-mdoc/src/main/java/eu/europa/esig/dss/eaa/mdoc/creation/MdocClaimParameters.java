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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.eaa.common.creation.AbstractAttestationClaimParameters;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Contains a list of selectively disclosable claims
 *
 */
public class MdocClaimParameters extends AbstractAttestationClaimParameters<MdocClaim> {

    /**
     * The user's birthdate approximate mask
     */
    private String birthdateApproximateMask;

    /**
     * User's place of birth (ISO/IEC 18013-5)
     */
    private String placeOfBirth;

    /**
     * User's nationality as a two letter country code (alpha-2 code) defined in ISO 3166-1
     */
    private String nationality;

    /**
     * A reproduction of the mDL holder’s portrait
     */
    private byte[] portrait;

    /**
     * Driving privileges of the mDL holder
     */
    private List<MdocDrivingPrivilege> drivingPrivileges;

    /**
     * The distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F
     */
    private String distinguishingSign;

    /**
     * The holder’s height in centimetres
     */
    private Integer height;

    /**
     * The holder’s weight in kilograms
     */
    private Integer weight;

    /**
     * The mDL holder’s eye colour
     */
    private String eyeColour;

    /**
     * The mDL holder’s hair colour
     */
    private String hairColour;

    /**
     * The date when portrait was taken
     */
    private Date portraitCaptureDate;

    /**
     * Biometric information of the mDL holder
     */
    private Map<String, byte[]> biometricTemplate;

    /**
     * Face ID biometric information of the mDL holder
     */
    private byte[] biometricTemplateFace;

    /**
     * An image of the signature or usual mark of the mDL holder
     */
    private byte[] signatureUsualMark;

    /**
     * A reproduction of the holder’s fingerprint data
     */
    private byte[] fingerprint;

    /**
     * A business name of the holder
     */
    private String businessName;

    /**
     * A name of legal person
     */
    private String organizationName;

    /**
     * The name(s) which holder was born
     */
    private String birthFullName;

    /**
     * The profession of the holder
     */
    private String profession;

    /**
     * The father of the holder
     */
    private String relationshipFather;

    /**
     * The mother of the holder
     */
    private String relationshipMother;

    /**
     * The parent of the holder
     */
    private String relationshipParent;

    /**
     * The son of the holder
     */
    private String relationshipSon;

    /**
     * The daughter of the holder
     */
    private String relationshipDaughter;

    /**
     * The brother of the holder
     */
    private String relationshipBrother;

    /**
     * The sister of the holder
     */
    private String relationshipSister;

    /**
     * The sibling of the holder
     */
    private String relationshipSibling;

    /**
     * The spouse of the holder
     */
    private String relationshipSpouse;

    /**
     * The father-in-law of the holder
     */
    private String relationshipFatherInLaw;

    /**
     * The mother-in-law of the holder
     */
    private String relationshipMotherInLaw;

    /**
     * The parent-in-law of the holder
     */
    private String relationshipParentInLaw;

    /**
     * The son-in-law of the holder
     */
    private String relationshipSonInLaw;

    /**
     * The daughter-in-law of the holder
     */
    private String relationshipDaughterInLaw;

    /**
     * The child-in-law of the holder
     */
    private String relationshipChildInLaw;

    /**
     * The parental authority of the holder
     */
    private String relationshipParentalAuthority;

    /**
     * The legal representative of the holder
     */
    private String relationshipLegalRepresentative;

    /**
     * The voluntary agent of the holder
     */
    private String relationshipAgent;

    /**
     * The document type
     */
    private String documentType;

    /**
     * The family name of the attribute subject
     */
    private String attestedAttributesSubjectFamilyName;

    /**
     * The given name of the attribute subject
     */
    private String attestedAttributesSubjectGivenName;

    /**
     * The number of the personal identification data assigned to the attribute subject
     */
    private String attestedAttributesSubjectDocumentNumber;

    /**
     * The subject attribute pseudonym
     */
    private String attestedAttributesSubjectPseudonym;

    /**
     * Default constructor
     */
    public MdocClaimParameters() {
        // empty
    }

    /**
     * Gets the user's birthday approximate mask
     *
     * @return {@link String}
     */
    public String getBirthdateApproximateMask() {
        return birthdateApproximateMask;
    }

    /**
     * Sets the user's birthday approximate mask. An 8 digit flag to denote the location of the mask
     * in YYYYMMDD format. 1 denotes mask. Issuing authority should pick one exact date to be used for full-date value.
     *
     * @param birthdateApproximateMask {@link String}
     */
    public void setBirthdateApproximateMask(String birthdateApproximateMask) {
        this.birthdateApproximateMask = birthdateApproximateMask;
    }

    /**
     * Gets user's place of birth
     *
     * @return {@link String}
     */
    public String getPlaceOfBirth() {
        return placeOfBirth;
    }

    /**
     * Sets user's place of birth
     *
     * @param placeOfBirth {@link String}
     */
    public void setPlaceOfBirth(String placeOfBirth) {
        this.placeOfBirth = placeOfBirth;
    }

    /**
     * Gets the user's nationality (used in ISO 118013-5 and ISO 23220-2)
     *
     * @return {@link String}
     */
    public String getNationality() {
        return nationality;
    }

    /**
     * Sets the user's nationality as a two letter country code (alpha-2 code) defined in ISO 3166-1.
     * This type of nationality providing is used within EAA documents conformant to ISO 118013-5 and ISO 23220-2.
     *
     * @param nationality {@link String}
     */
    public void setNationality(String nationality) {
        this.nationality = nationality;
    }

    /**
     * Gets a reproduction of the mDL holder’s portrait.
     *
     * @return byte array of the portrait
     */
    public byte[] getPortrait() {
        return portrait;
    }

    /**
     * Sets a reproduction of the mDL holder’s portrait.
     *
     * @param portrait byte array of the portrait
     */
    public void setPortrait(byte[] portrait) {
        this.portrait = portrait;
    }

    /**
     * Gets driving privileges of the mDL holder.
     *
     * @return a list of {@link MdocDrivingPrivilege}s
     */
    public List<MdocDrivingPrivilege> getDrivingPrivileges() {
        return drivingPrivileges;
    }

    /**
     * Sets driving privileges of the mDL holder.
     *
     * @param drivingPrivileges an array of {@link MdocDrivingPrivilege}s
     */
    public void setDrivingPrivileges(MdocDrivingPrivilege... drivingPrivileges) {
        if (Utils.isArrayNotEmpty(drivingPrivileges)) {
            this.drivingPrivileges = Arrays.asList(drivingPrivileges);
        } else {
            this.drivingPrivileges = null;
        }
    }

    /**
     * Sets driving privileges of the mDL holder.
     *
     * @param drivingPrivileges a list of {@link MdocDrivingPrivilege}s
     */
    public void setDrivingPrivileges(List<MdocDrivingPrivilege> drivingPrivileges) {
        this.drivingPrivileges = drivingPrivileges;
    }

    /**
     * Gets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @return {@link String}
     */
    public String getDistinguishingSign() {
        return distinguishingSign;
    }

    /**
     * Sets the distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F.
     * If no applicable distinguishing sign is available in ISO/IEC 18013-1, an IA may
     * use an empty identifier or another identifier by which it is internationally recognized.
     * In this case the IA should ensure there is no collision with other IA’s.
     *
     * @param distinguishingSign {@link String}
     */
    public void setDistinguishingSign(String distinguishingSign) {
        this.distinguishingSign = distinguishingSign;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link Number}
     */
    public Integer getHeight() {
        return height;
    }

    /**
     * Sets the holder’s height in centimetres
     *
     * @param height {@link Number}
     */
    public void setHeight(Integer height) {
        this.height = height;
    }

    /**
     * Gets the holder’s height in centimetres
     *
     * @return {@link Number}
     */
    public Integer getWeight() {
        return weight;
    }

    /**
     * Sets the holder’s height in centimetres
     *
     * @param weight {@link Number}
     */
    public void setWeight(Integer weight) {
        this.weight = weight;
    }

    /**
     * Gets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @return {@link String}
     */
    public String getEyeColour() {
        return eyeColour;
    }

    /**
     * Sets the mDL holder’s eye colour. The value shall be one of the following: “black”, “blue”,
     * “brown”, “dichromatic”, “grey”, “green”, “hazel”, “maroon”, “pink”, “unknown”.
     *
     * @param eyeColour {@link String}
     */
    public void setEyeColour(String eyeColour) {
        this.eyeColour = eyeColour;
    }

    /**
     * Gets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @return {@link String}
     */
    public String getHairColour() {
        return hairColour;
    }

    /**
     * Sets the mDL holder’s hair colour. The value shall be one of the following: “bald”, “black”,
     * “blond”, “brown”, “grey”, “red”, “auburn”, “sandy”, “white”, “unknown”.
     *
     * @param hairColour {@link String}
     */
    public void setHairColour(String hairColour) {
        this.hairColour = hairColour;
    }

    /**
     * Gets the date when portrait was taken.
     *
     * @return {@link Date}
     */
    public Date getPortraitCaptureDate() {
        return portraitCaptureDate;
    }

    /**
     * Sets the date when portrait was taken.
     *
     * @param portraitCaptureDate {@link Date}
     */
    public void setPortraitCaptureDate(Date portraitCaptureDate) {
        this.portraitCaptureDate = portraitCaptureDate;
    }

    /**
     * Gets a list of elements contains optional facial, fingerprint, iris, or other biometric information of the mDL
     * holder.
     *
     * @return a map of biometric template data
     */
    public Map<String, byte[]> getBiometricTemplate() {
        return biometricTemplate;
    }

    /**
     * Sets a list of elements contains optional facial, fingerprint, iris, or other biometric information of the mDL
     * holder.
     * A biometric template identifier has the format biometric_template_xx
     * where xx shall be replaced with the corresponding “Abstract value name” found in ISO/IEC 19785
     * 3:2020, Table 7, according to the following convention: capitalized characters are replaced with their
     * lowercase equivalent and spaces or non-alphanumeric characters are replaced by underscores (_).
     *
     * @param type {@link String} representing a biometric template type
     * @param data byte array containing the data value of the v
     */
    public void setBiometricTemplate(String type, byte[] data) {
        Objects.requireNonNull(type, "BiometricTemplate type cannot be null!");
        Objects.requireNonNull(data, "BiometricTemplate data cannot be null!");
        if (biometricTemplate == null) {
            this.biometricTemplate = new LinkedHashMap<>();
        }
        this.biometricTemplate.put(type, data);
    }

    /**
     * Gets biometric face Id of the mDL holder
     *
     * @return byte array
     */
    public byte[] getBiometricTemplateFace() {
        return biometricTemplateFace;
    }

    /**
     * Sets the face image of the mDL holder (holder's portrait)
     *
     * @param biometricTemplateFace byte array
     */
    public void setBiometricTemplateFace(byte[] biometricTemplateFace) {
        this.biometricTemplateFace = biometricTemplateFace;
    }

    /**
     * Gets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @return byte array
     */
    public byte[] getSignatureUsualMark() {
        return signatureUsualMark;
    }

    /**
     * Sets an image of the signature or usual mark of the mDL holder, see 7.2.7 ISO/IEC 18013-5.
     *
     * @param signatureUsualMark byte array
     */
    public void setSignatureUsualMark(byte[] signatureUsualMark) {
        this.signatureUsualMark = signatureUsualMark;
    }

    /**
     * Gets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @return the bytes of the fingerprint
     */
    public byte[] getFingerprint() {
        return fingerprint;
    }

    /**
     * Sets a reproduction of the holder’s fingerprint data (TBC).
     *
     * @param fingerprint the bytes of the fingerprint
     */
    public void setFingerprint(byte[] fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Gets a business name of the holder.
     *
     * @return {@link String}
     */
    public String getBusinessName() {
        return businessName;
    }

    /**
     * Sets a business name of the holder.
     *
     * @param businessName {@link String}
     */
    public void setBusinessName(String businessName) {
        this.businessName = businessName;
    }

    /**
     * Gets a name of legal person.
     *
     * @return {@link String}
     */
    public String getOrganizationName() {
        return organizationName;
    }

    /**
     * Sets a name of legal person.
     *
     * @param organizationName {@link String}
     */
    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    /**
     * Gets the name(s) which holder was born.
     *
     * @return {@link String}
     */
    public String getBirthFullName() {
        return birthFullName;
    }

    /**
     * Sets the name(s) which holder was born.
     *
     * @param birthFullName {@link String}
     */
    public void setBirthFullName(String birthFullName) {
        this.birthFullName = birthFullName;
    }

    /**
     * Gets the profession of the holder.
     *
     * @return {@link String}
     */
    public String getProfession() {
        return profession;
    }

    /**
     * Sets the profession of the holder.
     *
     * @param profession {@link String}
     */
    public void setProfession(String profession) {
        this.profession = profession;
    }

    /**
     * Gets the father of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipFather() {
        return relationshipFather;
    }

    /**
     * Sets the father of the holder
     *
     * @param relationshipFather {@link String}
     */
    public void setRelationshipFather(String relationshipFather) {
        this.relationshipFather = relationshipFather;
    }

    /**
     * Gets the mother of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipMother() {
        return relationshipMother;
    }

    /**
     * Sets the mother of the holder
     *
     * @param relationshipMother {@link String}
     */
    public void setRelationshipMother(String relationshipMother) {
        this.relationshipMother = relationshipMother;
    }

    /**
     * Gets the parent of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParent() {
        return relationshipParent;
    }

    /**
     * Sets the parent of the holder
     *
     * @param relationshipParent {@link String}
     */
    public void setRelationshipParent(String relationshipParent) {
        this.relationshipParent = relationshipParent;
    }

    /**
     * Gets the son of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSon() {
        return relationshipSon;
    }

    /**
     * Sets the son of the holder
     *
     * @param relationshipSon {@link String}
     */
    public void setRelationshipSon(String relationshipSon) {
        this.relationshipSon = relationshipSon;
    }

    /**
     * Gets the daughter of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipDaughter() {
        return relationshipDaughter;
    }

    /**
     * Sets the daughter of the holder
     *
     * @param relationshipDaughter {@link String}
     */
    public void setRelationshipDaughter(String relationshipDaughter) {
        this.relationshipDaughter = relationshipDaughter;
    }

    /**
     * Gets the brother of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipBrother() {
        return relationshipBrother;
    }

    /**
     * Sets the brother of the holder
     *
     * @param relationshipBrother {@link String}
     */
    public void setRelationshipBrother(String relationshipBrother) {
        this.relationshipBrother = relationshipBrother;
    }

    /**
     * Gets the sister of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSister() {
        return relationshipSister;
    }

    /**
     * Sets the sister of the holder
     *
     * @param relationshipSister {@link String}
     */
    public void setRelationshipSister(String relationshipSister) {
        this.relationshipSister = relationshipSister;
    }

    /**
     * Gets the sibling of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSibling() {
        return relationshipSibling;
    }

    /**
     * Sets the sibling of the holder
     *
     * @param relationshipSibling {@link String}
     */
    public void setRelationshipSibling(String relationshipSibling) {
        this.relationshipSibling = relationshipSibling;
    }

    /**
     * Gets the spouse of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSpouse() {
        return relationshipSpouse;
    }

    /**
     * Sets the spouse of the holder
     *
     * @param relationshipSpouse {@link String}
     */
    public void setRelationshipSpouse(String relationshipSpouse) {
        this.relationshipSpouse = relationshipSpouse;
    }

    /**
     * Gets the father-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipFatherInLaw() {
        return relationshipFatherInLaw;
    }

    /**
     * Sets the father-in-law of the holder
     *
     * @param relationshipFatherInLaw {@link String}
     */
    public void setRelationshipFatherInLaw(String relationshipFatherInLaw) {
        this.relationshipFatherInLaw = relationshipFatherInLaw;
    }

    /**
     * Gets the mother-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipMotherInLaw() {
        return relationshipMotherInLaw;
    }

    /**
     * Sets the mother-in-law of the holder
     *
     * @param relationshipMotherInLaw {@link String}
     */
    public void setRelationshipMotherInLaw(String relationshipMotherInLaw) {
        this.relationshipMotherInLaw = relationshipMotherInLaw;
    }

    /**
     * Gets the parent-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParentInLaw() {
        return relationshipParentInLaw;
    }

    /**
     * Sets the parent-in-law of the holder
     *
     * @param relationshipParentInLaw {@link String}
     */
    public void setRelationshipParentInLaw(String relationshipParentInLaw) {
        this.relationshipParentInLaw = relationshipParentInLaw;
    }

    /**
     * Gets the son-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipSonInLaw() {
        return relationshipSonInLaw;
    }

    /**
     * Sets the son-in-law of the holder
     *
     * @param relationshipSonInLaw {@link String}
     */
    public void setRelationshipSonInLaw(String relationshipSonInLaw) {
        this.relationshipSonInLaw = relationshipSonInLaw;
    }

    /**
     * Gets the daughter-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipDaughterInLaw() {
        return relationshipDaughterInLaw;
    }

    /**
     * Sets the daughter-in-law of the holder
     *
     * @param relationshipDaughterInLaw {@link String}
     */
    public void setRelationshipDaughterInLaw(String relationshipDaughterInLaw) {
        this.relationshipDaughterInLaw = relationshipDaughterInLaw;
    }

    /**
     * Gets the child-in-law of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipChildInLaw() {
        return relationshipChildInLaw;
    }

    /**
     * Sets the child-in-law of the holder
     *
     * @param relationshipChildInLaw {@link String}
     */
    public void setRelationshipChildInLaw(String relationshipChildInLaw) {
        this.relationshipChildInLaw = relationshipChildInLaw;
    }

    /**
     * Gets the parental authority of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipParentalAuthority() {
        return relationshipParentalAuthority;
    }

    /**
     * Sets the parental authority of the holder
     *
     * @param relationshipParentalAuthority {@link String}
     */
    public void setRelationshipParentalAuthority(String relationshipParentalAuthority) {
        this.relationshipParentalAuthority = relationshipParentalAuthority;
    }

    /**
     * Gets the legal representative of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipLegalRepresentative() {
        return relationshipLegalRepresentative;
    }

    /**
     * Sets the legal representative of the holder
     *
     * @param relationshipLegalRepresentative {@link String}
     */
    public void setRelationshipLegalRepresentative(String relationshipLegalRepresentative) {
        this.relationshipLegalRepresentative = relationshipLegalRepresentative;
    }

    /**
     * Gets the voluntary agent of the holder
     *
     * @return {@link String}
     */
    public String getRelationshipAgent() {
        return relationshipAgent;
    }

    /**
     * Sets the voluntary agent of the holder
     *
     * @param relationshipAgent {@link String}
     */
    public void setRelationshipAgent(String relationshipAgent) {
        this.relationshipAgent = relationshipAgent;
    }

    /**
     * Gets the document type.
     * NOTE: This a selectively disclosable property in comparison with {@code #getDocType}.
     *
     * @return {@link String}
     */
    public String getDocumentType() {
        return documentType;
    }

    /**
     * Sets the document type.
     * NOTE: This a selectively disclosable property in comparison with {@code #getDocType}.
     *
     * @param documentType {@link String}
     */
    public void setDocumentType(String documentType) {
        this.documentType = documentType;
    }

    /**
     * Gets the family name of the attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectFamilyName() {
        return attestedAttributesSubjectFamilyName;
    }

    /**
     * Gets the given name of the attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectGivenName() {
        return attestedAttributesSubjectGivenName;
    }

    /**
     * Gets the document number of the attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectDocumentNumber() {
        return attestedAttributesSubjectDocumentNumber;
    }

    /**
     * Sets the claim for associating a set of attributes to one entity different than the EAA subject,
     * when no pseudonym is used.
     *
     * @param familyName {@link String} the family name of the attribute subject
     * @param givenName {@link String} the given name of the attribute subject
     * @param documentNumber {@link String} the number of the personal identification data assigned to the attribute subject
     */
    public void setAttestedAttributesSubject(String familyName, String givenName, String documentNumber) {
        Objects.requireNonNull(familyName, "Attested Attributes Subject family name cannot be null!");
        Objects.requireNonNull(givenName, "Attested Attributes Subject given name cannot be null!");
        Objects.requireNonNull(documentNumber, "Attested Attributes Subject document number cannot be null!");
        this.attestedAttributesSubjectFamilyName = familyName;
        this.attestedAttributesSubjectGivenName = givenName;
        this.attestedAttributesSubjectDocumentNumber = documentNumber;
    }

    /**
     * Gets the pseudonym of the attribute subject
     *
     * @return {@link String}
     */
    public String getAttestedAttributesSubjectPseudonym() {
        return attestedAttributesSubjectPseudonym;
    }

    /**
     * Sets the claim for associating a set of attributes to one entity different than the EAA subject,
     * when pseudonym is used.
     *
     * @param pseudonym {@link String}  the subject attribute pseudonym
     */
    public void setAttestedAttributesSubjectPseudonym(String pseudonym) {
        Objects.requireNonNull(pseudonym, "Attested Attributes Subject pseudonym cannot be null!");
        this.attestedAttributesSubjectPseudonym = pseudonym;
    }

    /**
     * Adds a new selectively disclosable claim.
     * A hash will be computed for the claim.
     *
     * @param namespace {@link String}
     * @param name {@link String}
     * @param value {@link Object}
     */
    public void addClaim(final String namespace, final String name, final Object value) {
        Objects.requireNonNull(name, "Name cannot be null!");
        addClaim(MdocClaim.create(namespace, name, value));
    }

    @Override
    public String toString() {
        return "MdocEAAClaimParameters [" +
                "birthdateApproximateMask='" + birthdateApproximateMask + '\'' +
                ", placeOfBirth='" + placeOfBirth + '\'' +
                ", nationality='" + nationality + '\'' +
                ", portrait=" + Arrays.toString(portrait) +
                ", drivingPrivileges=" + drivingPrivileges +
                ", distinguishingSign='" + distinguishingSign + '\'' +
                ", height=" + height +
                ", weight=" + weight +
                ", eyeColour='" + eyeColour + '\'' +
                ", hairColour='" + hairColour + '\'' +
                ", portraitCaptureDate=" + portraitCaptureDate +
                ", biometricTemplate=" + biometricTemplate +
                ", biometricTemplateFace=" + Arrays.toString(biometricTemplateFace) +
                ", signatureUsualMark=" + Arrays.toString(signatureUsualMark) +
                ", fingerprint=" + Arrays.toString(fingerprint) +
                ", businessName='" + businessName + '\'' +
                ", organizationName='" + organizationName + '\'' +
                ", birthFullName='" + birthFullName + '\'' +
                ", profession='" + profession + '\'' +
                ", relationshipFather='" + relationshipFather + '\'' +
                ", relationshipMother='" + relationshipMother + '\'' +
                ", relationshipParent='" + relationshipParent + '\'' +
                ", relationshipSon='" + relationshipSon + '\'' +
                ", relationshipDaughter='" + relationshipDaughter + '\'' +
                ", relationshipBrother='" + relationshipBrother + '\'' +
                ", relationshipSister='" + relationshipSister + '\'' +
                ", relationshipSibling='" + relationshipSibling + '\'' +
                ", relationshipSpouse='" + relationshipSpouse + '\'' +
                ", relationshipFatherInLaw='" + relationshipFatherInLaw + '\'' +
                ", relationshipMotherInLaw='" + relationshipMotherInLaw + '\'' +
                ", relationshipParentInLaw='" + relationshipParentInLaw + '\'' +
                ", relationshipSonInLaw='" + relationshipSonInLaw + '\'' +
                ", relationshipDaughterInLaw='" + relationshipDaughterInLaw + '\'' +
                ", relationshipChildInLaw='" + relationshipChildInLaw + '\'' +
                ", relationshipParentalAuthority='" + relationshipParentalAuthority + '\'' +
                ", relationshipLegalRepresentative='" + relationshipLegalRepresentative + '\'' +
                ", relationshipAgent='" + relationshipAgent + '\'' +
                ", documentType='" + documentType + '\'' +
                ", attestedAttributesSubjectFamilyName='" + attestedAttributesSubjectFamilyName + '\'' +
                ", attestedAttributesSubjectGivenName='" + attestedAttributesSubjectGivenName + '\'' +
                ", attestedAttributesSubjectDocumentNumber='" + attestedAttributesSubjectDocumentNumber + '\'' +
                ", attestedAttributesSubjectPseudonym='" + attestedAttributesSubjectPseudonym + '\'' +
                "] " + super.toString();
    }

}
