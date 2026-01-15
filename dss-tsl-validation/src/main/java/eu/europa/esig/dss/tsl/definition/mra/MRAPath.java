package eu.europa.esig.dss.tsl.definition.mra;

import eu.europa.esig.dss.xades.definition.tsl.TrustedListElement;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.xpath.XPathQuery;

/**
 * Contains XPath expressions used within the implementation in relation to the MRA scheme
 *
 */
public class MRAPath extends AbstractPath {

    /** The path to reach a mra:CertificateContentDeclarationPointedParty element */
    public static final XPathQuery CERTIFICATE_CONTENT_DECLARATION_POINTED_PARTY_PATH = fromCurrentPosition(MRAElement.CERTIFICATE_CONTENT_DECLARATION_POINTED_PARTY);

    /** The path to reach a mra:CertificateContentDeclarationPointingParty element */
    public static final XPathQuery CERTIFICATE_CONTENT_DECLARATION_POINTING_PARTY_PATH = fromCurrentPosition(MRAElement.CERTIFICATE_CONTENT_DECLARATION_POINTING_PARTY);

    /** The path to reach a mra:CertificateContentReferenceEquivalence element */
    public static final XPathQuery CERTIFICATE_CONTENT_REFERENCES_EQUIVALENCE_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION,
            MRAElement.CERTIFICATE_CONTENT_REFERENCES_EQUIVALENCE_LIST, MRAElement.CERTIFICATE_CONTENT_REFERENCES_EQUIVALENCE);

    /** The path to reach a mra:CertificateContentReferenceEquivalenceContext element */
    public static final XPathQuery CERTIFICATE_CONTENT_REFERENCE_EQUIVALENCE_CONTEXT_PATH = fromCurrentPosition(MRAElement.CERTIFICATE_CONTENT_REFERENCE_EQUIVALENCE_CONTEXT);

    /** The path to reach a mra:MutualRecognitionAgreementInformation element */
    public static final XPathQuery MUTUAL_RECOGNITION_AGREEMENT_INFORMATION_PATH = all(MRAElement.MUTUAL_RECOGNITION_AGREEMENT_INFORMATION);

    /** The path to reach a mra:QualifierEquivalenceList element */
    public static final XPathQuery QUALIFIER_EQUIVALENCE_LIST_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION,
            MRAElement.TRUST_SERVICE_TSL_QUALIFICATION_EXTENSION_EQUIVALENCE_LIST, MRAElement.QUALIFIER_EQUIVALENCE_LIST);

    /** The path to reach a mra:TrustServiceTSLType/tl:ServiceTypeIdentifier element */
    public static final XPathQuery SERVICE_TYPE_IDENTIFIER_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_TSL_TYPE, TrustedListElement.SERVICE_TYPE_IDENTIFIER);

    /** The path to reach a mra:TrustServiceEquivalenceHistoryInstance element */
    public static final XPathQuery TRUST_SERVICE_EQUIVALENCE_HISTORY_INSTANCE_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION,
            MRAElement.TRUST_SERVICE_EQUIVALENCE_HISTORY, MRAElement.TRUST_SERVICE_EQUIVALENCE_HISTORY_INSTANCE);

    /** The path to reach a mra:TrustServiceEquivalenceInformation/mra:TrustServiceEquivalenceStatus element */
    public static final XPathQuery TRUST_SERVICE_EQUIVALENCE_INFORMATION_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_EQUIVALENCE_STATUS);

    /** The path to reach a mra:TrustServiceEquivalenceInformation/mra:TrustServiceEquivalenceStatusStartingTime element */
    public static final XPathQuery TRUST_SERVICE_EQUIVALENCE_INFORMATION_STATUS_STARTING_TIME_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_EQUIVALENCE_STATUS_STARTING_TIME);

    /** The path to reach a mra:TrustServiceEquivalenceStatus element */
    public static final XPathQuery TRUST_SERVICE_EQUIVALENCE_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_STATUS);

    /** The path to reach a mra:TrustServiceEquivalenceStatusStartingTime element */
    public static final XPathQuery TRUST_SERVICE_EQUIVALENCE_STATUS_STARTING_TIME_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_STATUS_STARTING_TIME);

    /** The path to reach a mra:MutualRecognitionAgreementInformation element */
    public static final XPathQuery TRUST_SERVICE_LEGAL_IDENTIFIER_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_LEGAL_IDENTIFIER);

    /** The path to reach a mra:TrustServiceTSLType element */
    public static final XPathQuery TRUST_SERVICE_TSL_TYPE_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_TSL_TYPE);

    /** The path to reach a mra:TrustServiceTSLTypeListPointedParty element */
    public static final XPathQuery TRUST_SERVICE_TSL_TYPE_LIST_POINTED_PARTY_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION,
            MRAElement.TRUST_SERVICE_TSL_TYPE_EQUIVALENCE_LIST, MRAElement.TRUST_SERVICE_TSL_TYPE_LIST_POINTED_PARTY);

    /** The path to reach a mra:TrustServiceTSLTypeListPointingParty element */
    public static final XPathQuery TRUST_SERVICE_TSL_TYPE_LIST_POINTING_PARTY_PATH = fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION,
            MRAElement.TRUST_SERVICE_TSL_TYPE_EQUIVALENCE_LIST, MRAElement.TRUST_SERVICE_TSL_TYPE_LIST_POINTING_PARTY);

    /** The path to reach a mra:TrustServiceTSLStatusInvalidEquivalence/mra:TrustServiceTSLStatusListPointedParty/tl:ServiceStatus element */
    public static final XPathQuery TRUST_SERVICE_TSL_STATUS_INVALID_EQUIVALENCE_LIST_POINTED_PARTY_SERVICE_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_TSL_STATUS_EQUIVALENCE_LIST,
                    MRAElement.TRUST_SERVICE_TSL_STATUS_INVALID_EQUIVALENCE, MRAElement.TRUST_SERVICE_TSL_STATUS_LIST_POINTED_PARTY,
                    TrustedListElement.SERVICE_STATUS);

    /** The path to reach a mra:TrustServiceTSLStatusInvalidEquivalence/mra:TrustServiceTSLStatusListPointingParty/tl:ServiceStatus element */
    public static final XPathQuery TRUST_SERVICE_TSL_STATUS_INVALID_EQUIVALENCE_LIST_POINTING_PARTY_SERVICE_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_TSL_STATUS_EQUIVALENCE_LIST,
                    MRAElement.TRUST_SERVICE_TSL_STATUS_INVALID_EQUIVALENCE, MRAElement.TRUST_SERVICE_TSL_STATUS_LIST_POINTING_PARTY,
                    TrustedListElement.SERVICE_STATUS);


    /** The path to reach a mra:TrustServiceTSLStatusValidEquivalence/mra:TrustServiceTSLStatusListPointedParty/tl:ServiceStatus element */
    public static final XPathQuery TRUST_SERVICE_TSL_STATUS_VALID_EQUIVALENCE_LIST_POINTED_PARTY_SERVICE_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_TSL_STATUS_EQUIVALENCE_LIST,
                    MRAElement.TRUST_SERVICE_TSL_STATUS_VALID_EQUIVALENCE, MRAElement.TRUST_SERVICE_TSL_STATUS_LIST_POINTED_PARTY,
                    TrustedListElement.SERVICE_STATUS);

    /** The path to reach a mra:TrustServiceTSLStatusValidEquivalence/mra:TrustServiceTSLStatusListPointingParty/tl:ServiceStatus element */
    public static final XPathQuery TRUST_SERVICE_TSL_STATUS_VALID_EQUIVALENCE_LIST_POINTING_PARTY_SERVICE_STATUS_PATH =
            fromCurrentPosition(MRAElement.TRUST_SERVICE_EQUIVALENCE_INFORMATION, MRAElement.TRUST_SERVICE_TSL_STATUS_EQUIVALENCE_LIST,
                    MRAElement.TRUST_SERVICE_TSL_STATUS_VALID_EQUIVALENCE, MRAElement.TRUST_SERVICE_TSL_STATUS_LIST_POINTING_PARTY,
                    TrustedListElement.SERVICE_STATUS);

    /**
     * Default constructor
     */
    public MRAPath() {
        // empty
    }

}
