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
 * Contains a list of header names as defined in "7 mDL data model" ISO/IEC 18013-5.
 *
 */
public final class ISO180135Headers {

    /**
     * Singleton
     */
    private ISO180135Headers() {
        // empty
    }

    /* Data elements from "Table 5 — Data elements" ISO/IEC 18013-5 */

    /** An audit control number assigned by the issuing authority */
    public static final String ADMINISTRATIVE_NUMBER = "administrative_number";

    /** The year when the mDL holder was born */
    public static final String AGE_BIRTH_YEAR = "age_birth_year";

    /** The age of the mDL holder */
    public static final String AGE_IN_YEARS = "age_in_years";

    /** Age attestation: Nearest “true” attestation above request, with NN being any value from 00 to 99 */
    public static final String AGE_OVER_NN = "age_over_";

    /** Day, month and year on which the mDL holder was born */
    public static final String BIRTH_DATE = "birth_date";

    /** This element contains optional facial biometric information of the mDL holder */
    public static final String BIOMETRIC_TEMPLATE_FACE = "biometric_template_face";

    /** This element contains optional facial, fingerprint, iris, or other biometric information of the mDL holder */
    public static final String BIOMETRIC_TEMPLATE_XX = "biometric_template_";

    /**  Country and municipality or state/province where the mDL holder was born */
    public static final String BIRTH_PLACE = "birth_place";

    /** Driving privileges of the mDL holder */
    public static final String DRIVING_PRIVILEGES = "driving_privileges";

    /** Date when mDL expires */
    public static final String EXPIRY_DATE = "expiry_date";

    /** mDL holder’s eye colour */
    public static final String EYE_COLOUR = "eye_colour";

    /** Last name, surname, or primary identifier, of the mDL holder */
    public static final String FAMILY_NAME = "family_name";

    /** The family name of the mDL holder using full UTF-8 character set */
    public static final String FAMILY_NAME_NATIONAL_CHARACTER = "family_name_national_character";

    /** First name(s), other name(s), or secondary identifier, of the mDL holder */
    public static final String GIVEN_NAME = "given_name";

    /** The given name of the mDL holder using full UTF-8 character set */
    public static final String GIVEN_NAME_NATIONAL_CHARACTER = "given_name_national_character";

    /** mDL holder’s hair colour */
    public static final String HAIR_COLOUR = "hair_colour";

    /** mDL holder’s height in centimetres */
    public static final String HEIGHT = "height";

    /** Date when mDL was issued */
    public static final String ISSUE_DATE = "issue_date";

    /** Issuing authority name */
    public static final String ISSUING_AUTHORITY = "issuing_authority";

    /** Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory */
    public static final String ISSUING_COUNTRY = "issuing_country";

    /** Country subdivision code of the jurisdiction that issued the mDL as defined in ISO 3166-2:2020, Clause 8 */
    public static final String ISSUING_JURISDICTION = "issuing_jurisdiction";

    /** The number assigned or calculated by the issuing authority */
    public static final String LICENCE_NUMBER = "document_number";

    /**  Nationality of the mDL holder as a two letter country code (alpha-2 code) defined in ISO 3166-1 */
    public static final String NATIONALITY = "nationality";

    /** The number assigned or calculated by the issuing authority */
    public static final String PORTRAIT = "portrait";

    /** Date when portrait was taken */
    public static final String PORTRAIT_CAPTURE_DATE = "portrait_capture_date";

    /** The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.) */
    public static final String RESIDENT_ADDRESS = "resident_address";

    /** The city where the mDL holder lives */
    public static final String RESIDENT_CITY = "resident_city";

    /** The country where the mDL holder lives as a two letter country code (alpha-2 code) defined in ISO 3166-1 */
    public static final String RESIDENT_COUNTRY = "resident_country";

    /** The postal code of the mDL holder */
    public static final String RESIDENT_POSTAL_CODE = "resident_postal_code";

    /** The state/province/district where the mDL holder lives */
    public static final String RESIDENT_STATE = "resident_state";

    /** mDL holder’s sex using values as defined in ISO/IEC 5218 */
    public static final String SEX = "sex";

    /** Image of the signature or usual mark of the  mDL holder, see 7.2.7 */
    public static final String SIGNATURE = "signature_usual_mark";

    /** Distinguishing sign of the issuing country according to ISO/IEC 18013-1:2018, Annex F */
    public static final String UN_DISTINGUISHING_SIGN = "un_distinguishing_sign";

    /**  mDL holder’s weight in kilograms */
    public static final String WEIGHT = "weight";

    /* Driving privileges as defined in "7.2.4 Categories of vehicles/restrictions/conditions" ISO/IEC 18013-5 */

    /** Code as per ISO/IEC 18013-2 Annex A */
    public static final String DRIVING_PRIVILEGES_CODE_CODE = "code";

    /** Array of code info */
    public static final String DRIVING_PRIVILEGES_CODES = "codes";

    /** Date of expiry encoded as full-date */
    public static final String DRIVING_PRIVILEGES_EXPIRY_DATE = "expiry_date";

    /** Date of issue encoded as full-date */
    public static final String DRIVING_PRIVILEGES_ISSUE_DATE = "issue_date";

    /** Sign as per ISO/IEC 18013-2 Annex A */
    public static final String DRIVING_PRIVILEGES_CODE_SIGN = "sign";

    /** Value as per ISO/IEC 18013-2 Annex A */
    public static final String DRIVING_PRIVILEGES_CODE_VALUE = "value";

    /** Vehicle category code as per ISO/IEC 18013-1 Annex B */
    public static final String DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE = "vehicle_category_code";

}
