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
package eu.europa.esig.dss.attestation.mdoc;

/**
 * Contains a list of header names as defined in "6.3 Standard meta-attributes" ISO/IEC 23220-2.
 *
 */
public final class ISO232202Headers {

    /**
     * Singleton
     */
    private ISO232202Headers() {
        // empty
    }

    /* Data elements from "Table 2 — Data elements for personal attributes" ISO/IEC 23220-2 */

    /** A reproduction of the holder’s portrait */
    public static final String BIOMETRIC_TEMPLATE_FACE = "biometric_template_face";

    /** Day, month and year on which the holder was born */
    public static final String BIRTH_DATE = "birth_date";

    /** Country and municipality or state/province where the holder was born */
    public static final String BIRTHPLACE = "birthplace";

    /** (Since ISO/IEC 23220-2:2026) Business name of the holder */
    public static final String BUSINESS_NAME = "business_name";

    /** Business name of the holder, Latin1 characters */
    public static final String BUSINESS_NAME_LATIN1 = "business_name_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) Business name of the holder */
    public static final String BUSINESS_NAME_UNICODE = "business_name_unicode";

    /** E-mail address of the holder */
    public static final String EMAIL_ADDRESS = "email_address";

    /** (Since ISO/IEC 23220-2:2026) Last name, surname, or primary identifier, of the holder */
    public static final String FAMILY_NAME = "family_name";

    /** Last name, surname, or primary identifier, of the holder, Latin1 characters */
    public static final String FAMILY_NAME_LATIN1 = "family_name_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) Last name, surname, or primary identifier, of the holder */
    public static final String FAMILY_NAME_UNICODE = "family_name_unicode";

    /** A reproduction of the holder’s fingerprint data (TBC) */
    public static final String FINGERPRINT = "fingerprint";

    /** (Since ISO/IEC 23220-2:2026) Full name of the holder */
    public static final String FULL_NAME = "full_name";

    /** (Since ISO/IEC 23220-2:2026) Full name of the holder. Latin1 characters */
    public static final String FULL_NAME_LATIN1 = "full_name_latin1";

    /** (Since ISO/IEC 23220-2:2026) First name(s), other name(s), or secondary identifier, of the holder */
    public static final String GIVEN_NAME = "given_name";

    /** First name(s), other name(s), or secondary identifier, of the holder. Latin1 characters */
    public static final String GIVEN_NAME_LATIN1 = "given_name_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) First name(s), other name(s), or secondary identifier, of the holder */
    public static final String GIVEN_NAME_UNICODE = "given_name_unicode";

    /** Holder’s height in centimetres */
    public static final String HEIGHT = "height";

    /** The name(s)which holder was born */
    public static final String NAME_AT_BIRTH = "name_at_birth";

    /** Nationality of the Holder as two letter country code (alpha-2 code) or three letter code alpha-3 code) defined in ISO 3166-1 */
    public static final String NATIONALITY = "nationality";

    /** (Since ISO/IEC 23220-2:2026) Name of legal person */
    public static final String ORGANIZATION_NAME = "organization_name";

    /** Name of legal person, Latin1 characters */
    public static final String ORGANIZATION_NAME_LATIN1 = "organization_name_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) Name of legal person */
    public static final String ORGANIZATION_NAME_UNICODE = "organization_name_unicode";

    /** Portrait data as specified in ISO/IEC 18013-2:2020, C.4.5 */
    public static final String PORTRAIT = "portrait";

    /** Date when portrait was taken */
    public static final String PORTRAIT_CAPTURE_DATE = "portrait_capture_date";

    /** Profession of the holder */
    public static final String PROFESSION = "profession";

    /** (Since ISO/IEC 23220-2:2026) The place where the holder resides and/or may be contacted (street/house number, municipality etc.) */
    public static final String RESIDENT_ADDRESS = "resident_address";

    /** The place where the holder resides and/or may be contacted (street/house number, municipality etc.), Latin 1 characters */
    public static final String RESIDENT_ADDRESS_LATIN1 = "resident_address_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) The place where the holder resides and/or may be contacted (street/house number, municipality etc.) */
    public static final String RESIDENT_ADDRESS_UNICODE = "resident_address_unicode";

    /** (Since ISO/IEC 23220-2:2026) The city/municipality (or equivalent) where the holder lives */
    public static final String RESIDENT_CITY = "resident_city";

    /** The city/municipality (or equivalent) where the holder lives, Latin 1 characters */
    public static final String RESIDENT_CITY_LATIN1 = "resident_city_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) The city/municipality (or equivalent) where the holder lives */
    public static final String RESIDENT_CITY_UNICODE = "resident_city_unicode";

    /** The country where the holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1 */
    public static final String RESIDENT_COUNTRY = "resident_country";

    /** The postal code of the holder */
    public static final String RESIDENT_POSTAL_CODE = "resident_postal_code";

    /** (Since ISO/IEC 23220-2:2026) The state (or equivalent) where the holder lives */
    public static final String RESIDENT_STATE = "resident_state";

    /** (Since ISO/IEC 23220-2:2026) The state (or equivalent) where the holder lives. Latin 1 characters */
    public static final String RESIDENT_STATE_LATIN1 = "resident_state_latin1";

    /** (Since ISO/IEC 23220-2:2026) The street and number (or equivalent, e.g. address line) where the holder lives. */
    public static final String RESIDENT_STREET = "resident_street";

    /** (Since ISO/IEC 23220-2:2026) The street and number (or equivalent, e.g. address line) where the holder lives, Latin 1 characters */
    public static final String RESIDENT_STREET_LATIN1 = "resident_street_latin1";

    /** Holder’s sex using values as defined in ISO/IEC 5218 */
    public static final String SEX = "sex";

    /** HTelephone number of the holder, including country code as specified ITU-T E.123 and ITU-T E.164 */
    public static final String TELEPHONE_NUMBER = "telephone_number";

    /** Academic title of the holder */
    public static final String TITLE = "title";

    /** Holder’s height in centimetres */
    public static final String WEIGHT = "weight";

    /* Data elements from "6.3.2.1 Data elements for attribute statements" ISO/IEC 23220-2 */

    /** The year when the holder was born */
    public static final String AGE_BIRTH_YEAR = "age_birth_year";

    /** The age of the holder */
    public static final String AGE_IN_YEARS = "age_in_years";

    /** Contians information if the holder is as old or older than a specified age, with NN being any value from 00 to 99 */
    public static final String AGE_OVER_NN = "age_over_";

    /* Data elements from "6.3.2.3 Relationship attributes" ISO/IEC 23220-2 */

    /** The voluntary agent of the holder */
    public static final String RELATIONSHIP_AGENT = "agent";

    /** The brother of the holder */
    public static final String RELATIONSHIP_BROTHER = "brother";

    /** The child-in-law of the holder */
    public static final String RELATIONSHIP_CHILD_IN_LAW = "child_in_law";

    /** The daughter of the holder */
    public static final String RELATIONSHIP_DAUGHTER = "daughter";

    /** The daughter-in-law of the holder */
    public static final String RELATIONSHIP_DAUGHTER_IN_LAW = "daughter_in_law";

    /** The father of the holder */
    public static final String RELATIONSHIP_FATHER = "father";

    /** The father-in-law of the holder */
    public static final String RELATIONSHIP_FATHER_IN_LAW = "father_in_law";

    /** The legal representative of the holder */
    public static final String RELATIONSHIP_LEGAL_REPRESENTATIVE = "legal_representative";

    /** The mother of the holder */
    public static final String RELATIONSHIP_MOTHER = "mother";

    /** The mother-in-law of the holder */
    public static final String RELATIONSHIP_MOTHER_IN_LAW = "mother_in_law";

    /** The parent of the holder */
    public static final String RELATIONSHIP_PARENT = "parent";

    /** The parent-in-law of the holder */
    public static final String RELATIONSHIP_PARENT_IN_LAW = "parent_in_law";

    /** The parental authority of the holder */
    public static final String RELATIONSHIP_PARENTAL_AUTHORITY = "parental_authority";

    /** The sibling of the holder */
    public static final String RELATIONSHIP_SIBLING = "sibling";

    /** The sister of the holder */
    public static final String RELATIONSHIP_SISTER = "sister";

    /** The son of the holder */
    public static final String RELATIONSHIP_SON = "son";

    /** The son-in-law of the holder */
    public static final String RELATIONSHIP_SON_IN_LAW = "son_in_law";

    /** The spouse the holder */
    public static final String RELATIONSHIP_SPOUSE = "spouse";

    /* Data elements from "6.3.3 Meta-attribute for issuer entity" ISO/IEC 23220-2 */

    /** (Since ISO/IEC 23220-2:2026) Name of issuing authority */
    public static final String ISSUING_AUTHORITY = "issuing_authority";

    /** Name of issuing authority, Latin1 characters */
    public static final String ISSUING_AUTHORITY_LATIN1 = "issuing_authority_latin1";

    /** (Deprecated since ISO/IEC 23220-2:2026) Name of issuing authority */
    public static final String ISSUING_AUTHORITY_UNICODE = "issuing_authority_unicode";

    /**
     * Country code as alpha 2 and alpha 3 code, defined in ISO 3166-1, which issued the mobile eID document or
     * within which the issuing authority is located
     */
    public static final String ISSUING_COUNTRY = "issuing_country";

    /**
     * Subdivision code as defined in ISO 3166-2, which issued the mobile eID document or within which
     * the issuing authority located
     */
    public static final String ISSUING_SUBDIVISION = "issuing_subdivision";

    /* Data elements from "6.3.4 Data elements for document entity" ISO/IEC 23220-2 */

    /** The number assigned or calculated by the issuing authority */
    public static final String DOCUMENT_NUMBER = "document_number";

    /** The document type */
    public static final String DOCUMENT_TYPE = "document_type";

    /** Date mobile eID document expires */
    public static final String EXPIRY_DATE = "expiry_date";

    /** DDate mobile eID document was issued */
    public static final String ISSUE_DATE = "issue_date";

    /* New Data elements from "Table 2 — Data elements for personal attributes" ISO/IEC 23220-2:2026 */

    /** Location of organization (e.g., postal address of organization */
    public static final String ORGANIZATION_LOCATION = "organization_location";

    /** Current legal name of legal person */
    public static final String CURRENT_LEGAL_NAME = "current_legal_name";

    /** VAT registration of legal person */
    public static final String VAT_REGISTRATION_NUMBER = "vat_registration_number";

    /** Tax reference number of legal person */
    public static final String TAX_REFERENCE_NUMBER = "tax_reference_number";

    /** Legal Identity number of legal person */
    public static final String LEGAL_ENTITY_IDENTIFIER = "legal_entity_identifier";

    /* 6.3.1.3 Date of birth structure */

    /** Approximate mask */
    public static final String APPROXIMATE_MASK = "approximate_mask";

}
