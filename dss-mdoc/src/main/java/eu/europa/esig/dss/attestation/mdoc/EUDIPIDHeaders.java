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
 * Contains a list of header names as defined in "3 ISO/IEC 18013-5-compliant encoding of PID" of PID Rulebook
 * (synchronized with v2.8.0).
 *
 */
public class EUDIPIDHeaders {

    /**
     * Singleton
     */
    private EUDIPIDHeaders() {
        // empty
    }

    /** PID "family_name" header */
    public static final String FAMILY_NAME = "family_name";

    /** PID "given_name" header */
    public static final String GIVEN_NAME = "given_name";

    /** PID "birth_date" header */
    public static final String BIRTH_DATE = "birth_date";

    /** PID "place_of_birth" header */
    public static final String PLACE_OF_BIRTH = "place_of_birth";

    /** PID "place_of_birth"/"country" header; a single alpha-2 country code as specified in ISO 3166-1 */
    public static final String PLACE_OF_BIRTH_COUNTRY = "country";

    /** PID "place_of_birth"/"region" header; the name of a state, province, district, or local area */
    public static final String PLACE_OF_BIRTH_REGION = "region";

    /** PID "place_of_birth"/"locality" header; the name of a municipality, city, town, or village */
    public static final String PLACE_OF_BIRTH_LOCALITY = "locality";

    /** PID "nationality" header */
    public static final String NATIONALITY = "nationality";

    /** PID "resident_address" header */
    public static final String RESIDENT_ADDRESS = "resident_address";

    /** PID "resident_country" header */
    public static final String RESIDENT_COUNTRY = "resident_country";

    /** PID "resident_state" header */
    public static final String RESIDENT_STATE = "resident_state";

    /** PID "resident_city" header */
    public static final String RESIDENT_CITY = "resident_city";

    /** PID "resident_postal_code" header */
    public static final String RESIDENT_POSTAL_CODE = "resident_postal_code";

    /** PID "resident_street" header */
    public static final String RESIDENT_STREET = "resident_street";

    /** PID "resident_house_number" header */
    public static final String RESIDENT_HOUSE_NUMBER = "resident_house_number";

    /** PID "personal_administrative_number" header */
    public static final String PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";

    /** PID "portrait" header */
    public static final String PORTRAIT = "portrait";

    /** PID "family_name_birth" header */
    public static final String FAMILY_NAME_BIRTH = "family_name_birth";

    /** PID "given_name_birth" header */
    public static final String GIVEN_NAME_BIRTH = "given_name_birth";

    /** PID "sex" header */
    public static final String SEX = "sex";

    /** PID "email_address" header */
    public static final String EMAIL_ADDRESS = "email_address";

    /** PID "mobile_phone_number" header */
    public static final String MOBILE_PHONE_NUMBER = "mobile_phone_number";

    /** PID "expiry_date" header */
    public static final String EXPIRY_DATE = "expiry_date";

    /** PID "issuing_authority" header */
    public static final String ISSUING_AUTHORITY = "issuing_authority";

    /** PID "issuing_country" header */
    public static final String ISSUING_COUNTRY = "issuing_country";

    /** PID "document_number" header */
    public static final String DOCUMENT_NUMBER = "document_number";

    /** PID "issuing_jurisdiction" header */
    public static final String ISSUING_JURISDICTION = "issuing_jurisdiction";

    /** PID "issuance_date" header */
    public static final String ISSUANCE_DATE = "issuance_date";

    /** PID "trust_anchor" header */
    public static final String TRUST_ANCHOR = "trust_anchor";

    /** PID "attestation_legal_category" header */
    public static final String ATTESTATION_LEGAL_CATEGORY = "attestation_legal_category";

}
