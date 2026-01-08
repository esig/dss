package eu.europa.esig.dss.xades.definition.tsl.mra;

import eu.europa.esig.dss.xades.definition.tsl.TrustedListNamespace;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;

public enum MRAElement implements DSSElement {

    /** CertificateContentDeclarationPointedParty */
    CERTIFICATE_CONTENT_DECLARATION_POINTED_PARTY("CertificateContentDeclarationPointedParty"),

    /** CertificateContentDeclarationPointingParty */
    CERTIFICATE_CONTENT_DECLARATION_POINTING_PARTY("CertificateContentDeclarationPointingParty"),

    /** CertificateContentReferenceEquivalenceContext */
    CERTIFICATE_CONTENT_REFERENCE_EQUIVALENCE_CONTEXT("CertificateContentReferenceEquivalenceContext"),

    /** CertificateContentReferenceEquivalence */
    CERTIFICATE_CONTENT_REFERENCES_EQUIVALENCE("CertificateContentReferenceEquivalence"),

    /** CertificateContentReferencesEquivalenceList */
    CERTIFICATE_CONTENT_REFERENCES_EQUIVALENCE_LIST("CertificateContentReferencesEquivalenceList"),

    /** MutualRecognitionAgreementInformation */
    MUTUAL_RECOGNITION_AGREEMENT_INFORMATION("MutualRecognitionAgreementInformation"),

    /** QcCClegislation */
    QC_CCLEGISLATION("QcCClegislation"),

    /** QcStatement */
    QC_STATEMENT("QcStatement"),

    /** QcStatementId */
    QC_STATEMENT_ID("QcStatementId"),

    /** QcStatementInfo */
    QC_STATEMENT_INFO("QcStatementInfo"),

    /** QcStatementSet */
    QC_STATEMENT_SET("QcStatementSet"),

    /** QcType */
    QC_TYPE("QcType"),

    /** QualifierEquivalence */
    QUALIFIER_EQUIVALENCE("QualifierEquivalence"),

    /** QualifierEquivalenceList */
    QUALIFIER_EQUIVALENCE_LIST("QualifierEquivalenceList"),

    /** QualifierPointedParty */
    QUALIFIER_POINTED_PARTY("QualifierPointedParty"),

    /** QualifierPointingParty */
    QUALIFIER_POINTING_PARTY("QualifierPointingParty"),

    /** TrustServiceEquivalenceHistory */
    TRUST_SERVICE_EQUIVALENCE_HISTORY("TrustServiceEquivalenceHistory"),

    /** TrustServiceEquivalenceHistoryInstance */
    TRUST_SERVICE_EQUIVALENCE_HISTORY_INSTANCE("TrustServiceEquivalenceHistoryInstance"),

    /** TrustServiceEquivalenceInformation */
    TRUST_SERVICE_EQUIVALENCE_INFORMATION("TrustServiceEquivalenceInformation"),

    /** TrustServiceEquivalenceStatus */
    TRUST_SERVICE_EQUIVALENCE_STATUS("TrustServiceEquivalenceStatus"),

    /** TrustServiceEquivalenceStatusStartingTime */
    TRUST_SERVICE_EQUIVALENCE_STATUS_STARTING_TIME("TrustServiceEquivalenceStatusStartingTime"),

    /** TrustServiceLegalIdentifier */
    TRUST_SERVICE_LEGAL_IDENTIFIER("TrustServiceLegalIdentifier"),

    /** TrustServiceTSLQualificationExtensionEquivalenceList */
    TRUST_SERVICE_TSL_QUALIFICATION_EXTENSION_EQUIVALENCE_LIST("TrustServiceTSLQualificationExtensionEquivalenceList"),

    /** TrustServiceTSLQualificationExtensionName */
    TRUST_SERVICE_TSL_QUALIFICATION_EXTENSION_NAME("TrustServiceTSLQualificationExtensionName"),

    /** TrustServiceTSLQualificationExtensionNamePointedParty */
    TRUST_SERVICE_TSL_QUALIFICATION_EXTENSION_NAME_POINTED_PARTY("TrustServiceTSLQualificationExtensionNamePointedParty"),

    /** TrustServiceTSLQualificationExtensionNamePointingParty */
    TRUST_SERVICE_TSL_QUALIFICATION_EXTENSION_NAME_POINTING_PARTY("TrustServiceTSLQualificationExtensionNamePointingParty"),

    /** TrustServiceTSLStatusEquivalenceList */
    TRUST_SERVICE_TSL_STATUS_EQUIVALENCE_LIST("TrustServiceTSLStatusEquivalenceList"),

    /** TrustServiceTSLStatusInvalidEquivalence */
    TRUST_SERVICE_TSL_STATUS_INVALID_EQUIVALENCE("TrustServiceTSLStatusInvalidEquivalence"),

    /** TrustServiceTSLStatusListPointedParty */
    TRUST_SERVICE_TSL_STATUS_LIST_POINTED_PARTY("TrustServiceTSLStatusListPointedParty"),

    /** TrustServiceTSLStatusListPointingParty */
    TRUST_SERVICE_TSL_STATUS_LIST_POINTING_PARTY("TrustServiceTSLStatusListPointingParty"),

    /** TrustServiceTSLStatusValidEquivalence */
    TRUST_SERVICE_TSL_STATUS_VALID_EQUIVALENCE("TrustServiceTSLStatusValidEquivalence"),

    /** TrustServiceTSLType */
    TRUST_SERVICE_TSL_TYPE("TrustServiceTSLType"),

    /** TrustServiceTSLTypeEquivalenceList */
    TRUST_SERVICE_TSL_TYPE_EQUIVALENCE_LIST("TrustServiceTSLTypeEquivalenceList"),

    /** TrustServiceTSLTypeListPointedParty */
    TRUST_SERVICE_TSL_TYPE_LIST_POINTED_PARTY("TrustServiceTSLTypeListPointedParty"),

    /** TrustServiceTSLTypeListPointingParty */
    TRUST_SERVICE_TSL_TYPE_LIST_POINTING_PARTY("TrustServiceTSLTypeListPointingParty");

    /** Namespace */
    private final DSSNamespace namespace;

    /** The tag name */
    private final String tagName;

    /**
     * Default constructor
     *
     * @param tagName {@link String}
     */
    MRAElement(String tagName) {
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
