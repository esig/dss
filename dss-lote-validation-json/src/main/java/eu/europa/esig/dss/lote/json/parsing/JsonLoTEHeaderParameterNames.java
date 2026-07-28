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
package eu.europa.esig.dss.lote.json.parsing;

/**
 * This class contains header definitions used within the TS 119 602 JSON List of Trusted Entities
 *
 */
public class JsonLoTEHeaderParameterNames {

    /**
     * Utils class
     */
    private JsonLoTEHeaderParameterNames() {
        // empty
    }

    /*
     * =========================
     * ROOT
     * =========================
     */

    /**
     * List of Trusted Entities root header parameter
     */
    public static final String LOTE = "LoTE";

    /*
     * =========================
     * LoTE
     * =========================
     */

    /** List and scheme information */
    public static final String LIST_AND_SCHEME_INFORMATION = "ListAndSchemeInformation";

    /** Trusted entities list */
    public static final String TRUSTED_ENTITIES_LIST = "TrustedEntitiesList";


    /*
     * =========================
     * ListAndSchemeInformation
     * =========================
     */

    /** LoTE version identifier */
    public static final String LOTE_VERSION_IDENTIFIER = "LoTEVersionIdentifier";

    /** LoTE sequence number */
    public static final String LOTE_SEQUENCE_NUMBER = "LoTESequenceNumber";

    /** LoTE type */
    public static final String LOTE_TYPE = "LoTEType";

    /** Scheme operator name */
    public static final String SCHEME_OPERATOR_NAME = "SchemeOperatorName";

    /** Scheme operator address */
    public static final String SCHEME_OPERATOR_ADDRESS = "SchemeOperatorAddress";

    /** Scheme name */
    public static final String SCHEME_NAME = "SchemeName";

    /** Scheme information URI */
    public static final String SCHEME_INFORMATION_URI = "SchemeInformationURI";

    /** Status determination approach */
    public static final String STATUS_DETERMINATION_APPROACH = "StatusDeterminationApproach";

    /** Scheme type community rules */
    public static final String SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules";

    /** Scheme territory */
    public static final String SCHEME_TERRITORY = "SchemeTerritory";

    /** Policy or legal notice */
    public static final String POLICY_OR_LEGAL_NOTICE = "PolicyOrLegalNotice";

    /** Historical information period */
    public static final String HISTORICAL_INFORMATION_PERIOD = "HistoricalInformationPeriod";

    /** Pointers to other LoTE */
    public static final String POINTERS_TO_OTHER_LOTE = "PointersToOtherLoTE";

    /** List issue date time */
    public static final String LIST_ISSUE_DATE_TIME = "ListIssueDateTime";

    /** Next update */
    public static final String NEXT_UPDATE = "NextUpdate";

    /** Distribution points */
    public static final String DISTRIBUTION_POINTS = "DistributionPoints";

    /** Scheme extensions */
    public static final String SCHEME_EXTENSIONS = "SchemeExtensions";


    /*
     * =========================
     * multiLangString
     * =========================
     */

    /** Language */
    public static final String LANG = "lang";

    /** Value */
    public static final String VALUE = "value";


    /*
     * =========================
     * NonEmptyMultiLangURI
     * =========================
     */

    /** Language */
    public static final String URI_LANG = "lang";

    /** URI value */
    public static final String URI_VALUE = "uriValue";


    /*
     * =========================
     * SchemeOperatorAddress
     * =========================
     */

    /** Scheme operator postal address */
    public static final String SCHEME_OPERATOR_POSTAL_ADDRESS = "SchemeOperatorPostalAddress";

    /** Scheme operator electronic address */
    public static final String SCHEME_OPERATOR_ELECTRONIC_ADDRESS = "SchemeOperatorElectronicAddress";


    /*
     * =========================
     * PostalAddress
     * =========================
     */

    /** Language */
    public static final String POSTAL_LANG = "lang";

    /** Street address */
    public static final String STREET_ADDRESS = "StreetAddress";

    /** Locality */
    public static final String LOCALITY = "Locality";

    /** State or province */
    public static final String STATE_OR_PROVINCE = "StateOrProvince";

    /** Postal code */
    public static final String POSTAL_CODE = "PostalCode";

    /** Country */
    public static final String COUNTRY = "Country";


    /*
     * =========================
     * OtherLoTEPointer
     * =========================
     */

    /** LoTE location */
    public static final String LOTE_LOCATION = "LoTELocation";

    /** Service digital identities */
    public static final String SERVICE_DIGITAL_IDENTITIES = "ServiceDigitalIdentities";

    /** LoTE qualifiers */
    public static final String LOTE_QUALIFIERS = "LoTEQualifiers";


    /*
     * =========================
     * ServiceDigitalIdentity
     * =========================
     */

    /** X509 certificates */
    public static final String X509_CERTIFICATES = "X509Certificates";

    /** X509 subject names */
    public static final String X509_SUBJECT_NAMES = "X509SubjectNames";

    /** Public key values */
    public static final String PUBLIC_KEY_VALUES = "PublicKeyValues";

    /** X509 subject key identifiers */
    public static final String X509_SKIS = "X509SKIs";

    /** Other identifiers */
    public static final String OTHER_IDS = "OtherIds";


    /*
     * =========================
     * pkiOb
     * =========================
     */

    /** Encoding */
    public static final String ENCODING = "encoding";

    /** Specification reference */
    public static final String SPEC_REF = "specRef";

    /** Value */
    public static final String VAL = "val";


    /*
     * =========================
     * LoTEQualifier
     * =========================
     */

    /** LoTE type */
    public static final String QUALIFIER_LOTE_TYPE = "LoTEType";

    /** Scheme operator name */
    public static final String QUALIFIER_SCHEME_OPERATOR_NAME = "SchemeOperatorName";

    /** Scheme type community rules */
    public static final String QUALIFIER_SCHEME_TYPE_COMMUNITY_RULES = "SchemeTypeCommunityRules";

    /** Scheme territory */
    public static final String QUALIFIER_SCHEME_TERRITORY = "SchemeTerritory";

    /** Mime type */
    public static final String MIME_TYPE = "MimeType";


    /*
     * =========================
     * TrustedEntity
     * =========================
     */

    /** Trusted entity information */
    public static final String TRUSTED_ENTITY_INFORMATION = "TrustedEntityInformation";

    /** Trusted entity services */
    public static final String TRUSTED_ENTITY_SERVICES = "TrustedEntityServices";


    /*
     * =========================
     * TrustedEntityService
     * =========================
     */

    /** Service information */
    public static final String SERVICE_INFORMATION = "ServiceInformation";

    /** Service history */
    public static final String SERVICE_HISTORY = "ServiceHistory";


    /*
     * =========================
     * ServiceInformation
     * =========================
     */

    /** Service name */
    public static final String SERVICE_NAME = "ServiceName";

    /** Service digital identity */
    public static final String SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity";

    /** Service type identifier */
    public static final String SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier";

    /** Service status */
    public static final String SERVICE_STATUS = "ServiceStatus";

    /** Status starting time */
    public static final String STATUS_STARTING_TIME = "StatusStartingTime";

    /** Scheme service definition URI */
    public static final String SCHEME_SERVICE_DEFINITION_URI = "SchemeServiceDefinitionURI";

    /** Service supply points */
    public static final String SERVICE_SUPPLY_POINTS = "ServiceSupplyPoints";

    /** Service definition URI */
    public static final String SERVICE_DEFINITION_URI = "ServiceDefinitionURI";

    /** Service information extensions */
    public static final String SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions";


    /*
     * =========================
     * ServiceSupplyPointURI
     * =========================
     */

    /** Service type */
    public static final String SERVICE_TYPE = "ServiceType";

    /** URI value */
    public static final String SERVICE_URI_VALUE = "uriValue";


    /*
     * =========================
     * ServiceHistoryInstance
     * =========================
     */

    /** Service name */
    public static final String HISTORY_SERVICE_NAME = "ServiceName";

    /** Service digital identity */
    public static final String HISTORY_SERVICE_DIGITAL_IDENTITY = "ServiceDigitalIdentity";

    /** Service status */
    public static final String HISTORY_SERVICE_STATUS = "ServiceStatus";

    /** Status starting time */
    public static final String HISTORY_STATUS_STARTING_TIME = "StatusStartingTime";

    /** Service type identifier */
    public static final String HISTORY_SERVICE_TYPE_IDENTIFIER = "ServiceTypeIdentifier";

    /** Service information extensions */
    public static final String HISTORY_SERVICE_INFORMATION_EXTENSIONS = "ServiceInformationExtensions";


    /*
     * =========================
     * TrustedEntityInformation
     * =========================
     */

    /** Trusted entity name */
    public static final String TE_NAME = "TEName";

    /** Trusted entity trade name */
    public static final String TE_TRADE_NAME = "TETradeName";

    /** Trusted entity address */
    public static final String TE_ADDRESS = "TEAddress";

    /** Trusted entity information URI */
    public static final String TE_INFORMATION_URI = "TEInformationURI";

    /** Trusted entity information extensions */
    public static final String TE_INFORMATION_EXTENSIONS = "TEInformationExtensions";


    /*
     * =========================
     * TEAddress
     * =========================
     */

    /** Trusted entity postal address */
    public static final String TE_POSTAL_ADDRESS = "TEPostalAddress";

    /** Trusted entity electronic address */
    public static final String TE_ELECTRONIC_ADDRESS = "TEElectronicAddress";

}
