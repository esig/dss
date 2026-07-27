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
package eu.europa.esig.dss.attestation.sd.jwt;

/**
 * Contains a list of SD-JWT constants requiring for processing the token
 *
 */
public class SDJWTConstants {

    /**
     * Utils class
     */
    private SDJWTConstants() {
        // singleton
    }

    // SD-JWT unprotected header parameters

    /** SD-JWT unprotected header "disclosures" header */
    public static final String DISCLOSURES = "disclosures";

    /** SD-JWT unprotected header "kb_jwt" (key binding JWT) header */
    public static final String KB_JWT = "kb_jwt";

    // SD-JWT payload parameters

    // Key Binding payload parameters

    /** SD-JWT key binding payload "sd_hash" header */
    public static final String SD_HASH = "sd_hash";

    // RFC 9901 payload header parameters

    /** SD-JWT payload header used to define a hash value of a selectively disclosable array element */
    public static final String HASH = "...";

    /** SD-JWT payload "_sd" header */
    public static final String _SD = "_sd";

    /** SD-JWT payload "_sd_alg" header */
    public static final String _SD_ALG = "_sd_alg";

    /** SD-JWT payload "cnf" header */
    public static final String CNF = "cnf";

    // RFC 7519 claims

    /** 4.1.1. "iss" (Issuer) Claim */
    public static final String ISSUER = "iss";

    /** 4.1.2. "sub" (Subject) Claim */
    public static final String SUBJECT = "sub";

    /** 4.1.3. "aud" (Audience) Claim */
    public static final String AUDIENCE = "aud";

    /** 4.1.4. "exp" (Expiration Time) Claim */
    public static final String EXPIRATION_TIME = "exp";

    /** 4.1.5. "nbf" (Not Before) Claim */
    public static final String NOT_BEFORE = "nbf";

    /** 4.1.6. "iat" (Issued At) Claim */
    public static final String ISSUED_AT = "iat";

    /** 4.1.7. "jti" (JWT ID) Claim */
    public static final String JWT_ID = "jti";

    // draft-ietf-oauth-sd-jwt-vc-13

    /** The integrity of a claim document or value */
    public static final String INTEGRITY_SUFFIX = "#integrity";

    /** The type of the Verifiable Credential */
    public static final String VERIFIABLE_CREDENTIALS_TYPE = "vct";

    /** The hash of the Type Metadata document to provide integrity */
    public static final String VERIFIABLE_CREDENTIALS_INTEGRITY = "vct#integrity";

    // draft-ietf-oauth-revocation-list-13

    /** Specifies a JSON Object that contains at least one reference to a revocation mechanism */
    public static final String STATUS = "status";

    /** Specifies a JSON Object that contains a reference to a Status List Token */
    public static final String STATUS_LIST = "status_list";

    /** A certificate used to sign the top-level certificate in the x5chain element in the MSO revocation list structure */
    public static final String STATUS_LIST_CERTIFICATE = "certificate";

    /** A non-negative Integer that represents the index to check for revocation information for the current Token */
    public static final String STATUS_LIST_IDX = "idx";

    /** String value that identifies the Status List Token containing the revocation information for the Token */
    public static final String STATUS_LIST_URI = "uri";

    /** Specifies a CBOR Object that contains a reference to an Identifier List */
    public static final String IDENTIFIER_LIST = "identifier_list";

    /** Unique identifier of the token */
    public static final String IDENTIFIER_LIST_ID = "id";

    /** String value that identifies the Identifier List containing the revocation information for the Token */
    public static final String IDENTIFIER_LIST_URI = "uri";

    /** A certificate used to sign the top-level certificate in the x5chain element in the MSO revocation list structure */
    public static final String IDENTIFIER_LIST_CERTIFICATE = "certificate";

    // ETSI TS 119 472-1 defined "status" headers

    /** A non-negative Integer that represents the index to check for revocation information for the current Token */
    public static final String STATUS_INDEX = "index";

    /** Purpose of the revocation entry claim */
    public static final String STATUS_PURPOSE = "purpose";

    /** An identifier of the type of the revocation information provided by the service */
    public static final String STATUS_TYPE = "type";

    /** String value that identifies the Status List Token containing the revocation information for the Token */
    public static final String STATUS_URI = "uri";

    // RFC 9449 Nonce

    /** Value used to associate a Client session with an ID Token */
    public static final String NONCE = "nonce";

    // OpenID Connect Core 1.0 (User information claims)

    /** End-User's full name */
    public static final String USER_NAME = "name";

    /** Given name(s) or first name(s) of the End-User */
    public static final String USER_GIVEN_NAME = "given_name";

    /** Surname(s) or last name(s) of the End-User */
    public static final String USER_FAMILY_NAME = "family_name";

    /** Middle name(s) of the End-User */
    public static final String USER_MIDDLE_NAME = "middle_name";

    /** Casual name of the End-User */
    public static final String USER_NICKNAME = "nickname";

    /** Shorthand name by which the End-User wishes to be referred */
    public static final String USER_PREFERRED_NICKNAME = "preferred_username";

    /** URL of the End-User's profile page */
    public static final String USER_PROFILE = "profile";

    /** URL of the End-User's profile picture */
    public static final String USER_PICTURE = "picture";

    /** URL of the End-User's Web page or blog */
    public static final String USER_WEBSITE = "website";

    /** End-User's preferred e-mail address */
    public static final String USER_EMAIL = "email";

    /** End-User's preferred e-mail address */
    public static final String USER_EMAIL_VERIFIED = "email_verified";

    /** End-User's gender */
    public static final String USER_GENDER = "gender";

    /** End-User's birthday */
    public static final String USER_BIRTHDATE = "birthdate";

    /** End-User's time zone */
    public static final String USER_ZONEINFO = "zoneinfo";

    /** End-User's locale */
    public static final String USER_LOCALE = "locale";

    /** End-User's preferred telephone number */
    public static final String USER_PHONE_NUMBER = "phone_number";

    /** If the End-User's phone number has been verified */
    public static final String USER_PHONE_NUMBER_VERIFIED = "phone_number_verified";

    /** End-User's preferred postal address */
    public static final String USER_ADDRESS = "address";

    /** End-User's full mailing address */
    public static final String USER_ADDRESS_FORMATTED = "formatted";

    /** End-User's full street address component */
    public static final String USER_ADDRESS_STREET_ADDRESS = "street_address";

    /** End-User's city or locality component */
    public static final String USER_ADDRESS_LOCALITY = "locality";

    /** End-User's state, province, prefecture, or region component */
    public static final String USER_ADDRESS_REGION = "region";

    /** End-User's zip code or postal code component */
    public static final String USER_ADDRESS_POSTAL_CODE = "postal_code";

    /** End-User's country name component */
    public static final String USER_ADDRESS_COUNTRY = "country";

    /** Time the End-User's information was last updated */
    public static final String UPDATED_AT = "updated_at";

    // OpenID Connect for Identity Assurance Claims Registration 1.0

    /** End-user's place of birth */
    public static final String USER_PLACE_OF_BIRTH = "place_of_birth";

    /** String representing country in [ISO 3166-1] Alpha-2 or [ISO 3166-3] syntax */
    public static final String USER_PLACE_OF_BIRTH_COUNTRY = "country";

    /** String representing state, province, prefecture, or region component */
    public static final String USER_PLACE_OF_BIRTH_REGION = "region";

    /** String representing city or locality component */
    public static final String USER_PLACE_OF_BIRTH_LOCALITY = "locality";

    /** End-user's nationalities using ICAO 3-letter codes, 2-letter ICAO codes may be used */
    public static final String USER_NATIONALITIES = "nationalities";

    /** End-user's family name(s) when they were born */
    public static final String USER_BIRTH_FAMILY_NAME = "birth_family_name";

    /** End-user's given name(s) when they were born */
    public static final String USER_BIRTH_GIVEN_NAME = "birth_given_name";

    /** End-user's middle name(s) when they were born */
    public static final String USER_BIRTH_MIDDLE_NAME = "birth_middle_name";

    /** End-user's salutation */
    public static final String USER_SALUTATION = "salutation";

    /** End-user's title */
    public static final String USER_TITLE = "title";

    /** End-user's mobile phone number formatted according to ITU-T recommendation */
    public static final String USER_MOBILE_PHONE_NUMBER = "msisdn";

    /** Stage name, religious name or any other type of alias/pseudonym */
    public static final String USER_PSEUDONYM = "also_known_as";

    // ETSI TS 119 472-1 qualified claims

    /** SD-JWT payload "category" header */
    public static final String CATEGORY = "category";

    /** SD-JWT payload "iss_reg_id" header */
    public static final String ISSUING_REGISTRATION_IDENTIFIER = "iss_reg_id";

    /** SD-JWT payload "adm_nbf" header */
    public static final String ADMINISTRATIVE_VALIDITY_NOT_BEFORE = "adm_nbf";

    /** SD-JWT payload "adm_exp" header */
    public static final String ADMINISTRATIVE_VALIDITY_EXPIRY= "adm_exp";

    /** SD-JWT payload "oneTime" header */
    public static final String ONE_TIME = "oneTime";

    /** SD-JWT payload "shortLived" header */
    public static final String SHORT_LIVED = "shortLived";

    /** SD-JWT payload "subAttrs" header */
    public static final String ATTESTED_ATTRIBUTES_SUBJECT = "subAttrs";

    /** SD-JWT payload "sub_id" header of the attested attributes subject header */
    public static final String ATTESTED_ATTRIBUTES_SUBJECT_ID = "sub_id";

    /** SD-JWT payload "sub_aka" header of the attested attributes subject header */
    public static final String ATTESTED_ATTRIBUTES_SUBJECT_AKA = "sub_aka";

    /** SD-JWT payload "attrs" header of the attested attributes subject header */
    public static final String ATTESTED_ATTRIBUTES_SUBJECT_ATTRIBUTES = "attrs";

    // W3C Verifiable Credentials Data Model v2.0

    /** SD-JWT payload "credentialSubject" header */
    public static final String CREDENTIAL_SUBJECT = "credentialSubject";

    // PID Rulebook claims (last synchronized with ARF v2.8.0)
    // {@see https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/main/rulebooks/pid/pid-rulebook.md}

    /** SD-JWT payload "date_of_expiry" header */
    public static final String EXPIRY_DATE = "date_of_expiry";

    /** SD-JWT payload "date_of_issuance" header */
    public static final String ISSUANCE_DATE = "date_of_issuance";

    /** SD-JWT payload "personal_administrative_number" header */
    public static final String PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";

    /** SD-JWT payload "sex" header */
    public static final String SEX = "sex";

    /** End-User's address's house number component */
    public static final String USER_ADDRESS_HOUSE_NUMBER = "house_number";

    /** SD-JWT payload "document_number" header */
    public static final String DOCUMENT_NUMBER = "document_number";

    /** SD-JWT payload "issuing_authority" header */
    public static final String ISSUING_AUTHORITY = "issuing_authority";

    /** SD-JWT payload "issuing_country" header */
    public static final String ISSUING_COUNTRY = "issuing_country";

    /** SD-JWT payload "issuing_jurisdiction" header */
    public static final String ISSUING_JURISDICTION = "issuing_jurisdiction";

    /** SD-JWT payload "age_in_years" header */
    public static final String AGE_IN_YEARS = "age_in_years";

    /** SD-JWT payload "age_birth_year" header */
    public static final String AGE_BIRTH_YEAR = "age_birth_year";

    /** SD-JWT payload "age_equal_or_over" header */
    public static final String AGE_EQUAL_OR_OVER = "age_equal_or_over";

    /** SD-JWT payload "trust_anchor" header */
    public static final String TRUST_ANCHOR = "trust_anchor";

    /** SD-JWT payload "attestation_legal_category" header */
    public static final String ATTESTATION_LEGAL_CATEGORY = "attestation_legal_category";

    // RFC 7800 "Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)" claims

    /** Confirmation claim "jku" header */
    public static final String JKU = "jku";

    /** Confirmation claim "jwe" header */
    public static final String JWE = "jwe";

    /** Confirmation claim "jwk" header */
    public static final String JWK = "jwk";

    /** Confirmation claim "kid" header */
    public static final String KID = "kid";

    // RFC 7517 "JSON Web Key (JWK)" claims

    /** JWT "kty" header */
    public static final String KTY = "kty";

    /** Confirmation claim "x5c" header */
    public static final String X5C = "x5c";

    /** Confirmation claim "x5u" header */
    public static final String X5U = "x5u";

    /** Confirmation claim "x5t#S256" header */
    public static final String X5TS526 = "x5t#S256";

    // RFC 7518 "JSON Web Algorithms (JWA)" claims

    /** Confirmation claim EC "crv" header */
    public static final String EC_CRV = "crv";

    /** Confirmation claim EC "x" header */
    public static final String EC_X = "x";

    /** Confirmation claim EC "y" header */
    public static final String EC_Y = "y";

    /** Confirmation claim RSA exponent "e" header */
    public static final String RSA_E = "e";

    /** Confirmation claim RSA modulus "n" header */
    public static final String RSA_N = "n";

    // RFC 8037 "CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)" claims

    /** Confirmation claim OKP "crv" header */
    public static final String OKP_CRV = "crv";

    /** Confirmation claim OKP "x" header */
    public static final String OKP_X = "x";

    // OpenID Identity Assurance Schema Definition 1.0 claims

    /** SD-JWT payload "evidence" header */
    public static final String EVIDENCE = "evidence";

}
