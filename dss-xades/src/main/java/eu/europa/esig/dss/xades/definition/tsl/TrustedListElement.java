package eu.europa.esig.dss.xades.definition.tsl;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

/**
 * Contains a list of TS 119 612 XSD Trusted List elements.
 *
 */
public enum TrustedListElement implements DSSElement {

    /** AdditionalInformation */
    ADDITIONAL_INFORMATION("AdditionalInformation"),

    /** AdditionalServiceInformation */
    ADDITIONAL_SERVICE_INFORMATION("AdditionalServiceInformation"),

    /** CountryName */
    COUNTRY_NAME("CountryName"),

    /** dateTime */
    DATE_TIME("dateTime"),

    /** DigitalId */
    DIGITAL_ID("DigitalId"),

    /** DistributionPoints */
    DISTRIBUTION_POINTS("DistributionPoints"),

    /** ElectronicAddress */
    ELECTRONIC_ADDRESS("ElectronicAddress"),

    /** ExpiredCertsRevocationInfo */
    EXPIRED_CERTS_REVOCATION_INFO("ExpiredCertsRevocationInfo"),

    /** Extension */
    EXTENSION("Extension"),

    /** HistoricalInformationPeriod */
    HISTORICAL_INFORMATION_PERIOD("HistoricalInformationPeriod"),

    /** InformationValue */
    INFORMATION_VALUE("InformationValue"),

    /** ListIssueDateTime */
    LIST_ISSUE_DATE_TIME("ListIssueDateTime"),

    /** Locality */
    LOCALITY("Locality"),

    /** Name */
    NAME("Name"),

    /** NextUpdate */
    NEXT_UPDATE("NextUpdate"),

    /** Other */
    OTHER("Other"),

    /** OtherInformation */
    OTHER_INFORMATION("OtherInformation"),

    /** OtherTSLPointer */
    OTHER_TSL_POINTER("OtherTSLPointer"),

    /** PointersToOtherTSL */
    POINTERS_TO_OTHER_TSL("PointersToOtherTSL"),

    /** PolicyOrLegalNotice */
    POLICY_OR_LEGAL_NOTICE("PolicyOrLegalNotice"),

    /** PostalAddress */
    POSTAL_ADDRESS("PostalAddress"),

    /** PostalAddresses */
    POSTAL_ADDRESSES("PostalAddresses"),

    /** PostalCode */
    POSTAL_CODE("PostalCode"),

    /** SchemeExtensions */
    SCHEME_EXTENSION("SchemeExtensions"),

    /** SchemeInformation */
    SCHEME_INFORMATION("SchemeInformation"),

    /** SchemeInformationURI */
    SCHEME_INFORMATION_URI("SchemeInformationURI"),

    /** SchemeName */
    SCHEME_NAME("SchemeName"),

    /** SchemeOperatorAddress */
    SCHEME_OPERATOR_ADDRESS("SchemeOperatorAddress"),

    /** SchemeOperatorName */
    SCHEME_OPERATOR_NAME("SchemeOperatorName"),

    /** SchemeServiceDefinitionURI */
    SCHEME_SERVICE_DEFINITION_URI("SchemeServiceDefinitionURI"),

    /** SchemeTerritory */
    SCHEME_TERRITORY("SchemeTerritory"),

    /** SchemeTypeCommunityRules */
    SCHEME_TYPE_COMMUNITY_RULES("SchemeTypeCommunityRules"),

    /** ServiceDigitalIdentity */
    SERVICE_DIGITAL_IDENTITY("ServiceDigitalIdentity"),

    /** ServiceDigitalIdentities */
    SERVICE_DIGITAL_IDENTITIES("ServiceDigitalIdentities"),

    /** ServiceHistory */
    SERVICE_HISTORY("ServiceHistory"),

    /** ServiceHistoryInstance */
    SERVICE_HISTORY_INSTANCE("ServiceHistoryInstance"),

    /** ServiceInformation */
    SERVICE_INFORMATION("ServiceInformation"),

    /** ServiceInformationExtensions */
    SERVICE_INFORMATION_EXTENSIONS("ServiceInformationExtensions"),

    /** ServiceTypeIdentifier */
    SERVICE_TYPE_IDENTIFIER("ServiceTypeIdentifier"),

    /** ServiceName */
    SERVICE_NAME("ServiceName"),

    /** ServiceStatus */
    SERVICE_STATUS("ServiceStatus"),

    /** ServiceSupplyPoint */
    SERVICE_SUPPLY_POINT("ServiceSupplyPoint"),

    /** ServiceSupplyPoints */
    SERVICE_SUPPLY_POINTS("ServiceSupplyPoints"),

    /** StateOrProvince */
    STATE_OR_PROVINCE("StateOrProvince"),

    /** StatusDeterminationApproach */
    STATUS_DETERMINATION_APPROACH("StatusDeterminationApproach"),

    /** StatusStartingTime */
    STATUS_STARTING_TIME("StatusStartingTime"),

    /** StreetAddress */
    STREET_ADDRESS("StreetAddress"),

    /** TextualInformation */
    TEXTUAL_INFORMATION("TextualInformation"),

    /** TrustServiceProvider */
    TRUST_SERVICE_PROVIDER("TrustServiceProvider"),

    /** TrustServiceProviderList */
    TRUST_SERVICE_PROVIDER_LIST("TrustServiceProviderList"),

    /** TrustServiceStatusList */
    TRUST_SERVICE_STATUS_LIST("TrustServiceStatusList"),

    /** TSPAddress */
    TSL_ADDRESS("TSPAddress"),

    /** TSPInformation */
    TSL_INFORMATION("TSPInformation"),

    /** TSPInformationExtensions */
    TSL_INFORMATION_EXTENSIONS("TSPInformationExtensions"),

    /** TSPInformationURI */
    TSL_INFORMATION_URI("TSPInformationURI"),

    /** TSLLegalNotice */
    TSL_LEGAL_NOTICE("TSLLegalNotice"),

    /** TSLLocation */
    TSL_LOCATION("TSLLocation"),

    /** TSPName */
    TSL_NAME("TSPName"),

    /** TSLPolicy */
    TSL_POLICY("TSLPolicy"),

    /** TSLSequenceNumber */
    TSL_SEQUENCE_NUMBER("TSLSequenceNumber"),

    /** TSLType */
    TSL_TYPE("TSLType"),

    /** TSLVersionIdentifier */
    TSL_VERSION_IDENTIFIER("TSLVersionIdentifier"),

    /** TSPService */
    TSP_SERVICE("TSPService"),

    /** TSPServices */
    TSP_SERVICES("TSPServices"),

    /** TSPServiceDefinitionURI */
    TSP_SERVICE_DEFINITION_URI("TSPServiceDefinitionURI"),

    /** TSPTradeName */
    TSP_TRADE_NAME("TSPTradeName"),

    /** URI */
    URI("URI"),

    /** X509Certificate */
    X509_CERTIFICATE("X509Certificate"),

    /** X509SKI */
    X509_SKI("X509SKI"),

    /** X509SubjectName */
    X509_SUBJECT_NAME("X509SubjectName");

    /** Namespace */
    private final DSSNamespace namespace;

    /** The tag name */
    private final String tagName;

    /**
     * Default constructor
     *
     * @param tagName {@link String}
     */
    TrustedListElement(String tagName) {
        this.tagName = tagName;
        this.namespace = TrustedListNamespace.NS;
    }

    @Override
    public DSSNamespace getNamespace() {
        return namespace;
    }

    @Override
    public String getTagName() {
        return tagName;
    }

    @Override
    public String getURI() {
        return namespace.getUri();
    }

    @Override
    public boolean isSameTagName(String value) {
        return tagName.equals(value);
    }

}
