package eu.europa.esig.xmlers.definition;

import eu.europa.esig.dss.jaxb.common.definition.DSSElement;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;

/**
 * XMLERS elements
 *
 */
public enum XMLERSElement implements DSSElement {

    /** EvidenceRecord */
    EVIDENCE_RECORD("EvidenceRecord"),

    /** EncryptionInformation */
    ENCRYPTION_INFORMATION("EncryptionInformation"),

    /** EncryptionInformationType */
    ENCRYPTION_INFORMATION_TYPE("EncryptionInformationType"),

    /** EncryptionInformationValue */
    ENCRYPTION_INFORMATION_VALUE("EncryptionInformationValue"),

    /** ArchiveTimeStampSequence */
    ARCHIVE_TIME_STAMP_SEQUENCE("ArchiveTimeStampSequence"),

    /** ArchiveTimeStampChain */
    ARCHIVE_TIME_STAMP_CHAIN("ArchiveTimeStampChain"),

    /** DigestMethod */
    DIGEST_METHOD("DigestMethod"),

    /** CanonicalizationMethod */
    CANONICALIZATION_METHOD("CanonicalizationMethod"),

    /** EncryptionInformation */
    ARCHIVE_TIME_STAMP("ArchiveTimeStamp"),

    /** HashTree */
    HASH_TREE("HashTree"),

    /** TimeStamp */
    TIME_STAMP("TimeStamp"),

    /** Attributes */
    ATTRIBUTES("Attributes"),

    /** TimeStampToken */
    TIME_STAMP_TOKEN("TimeStampToken"),

    /** CryptographicInformationList */
    CRYPTOGRAPHIC_INFORMATION_LIST("CryptographicInformationList"),

    /** Sequence */
    SEQUENCE("Sequence"),

    /** DigestValue */
    DIGEST_VALUE("DigestValue"),

    /** Attribute */
    ATTRIBUTE("Attribute"),

    /** SupportingInformationList */
    SUPPORTING_INFORMATION_LIST("SupportingInformationList"),

    /** SupportingInformation */
    SUPPORTING_INFORMATION("SupportingInformation");

    /** Namespace */
    private final DSSNamespace namespace;

    /** The tag name */
    private final String tagName;

    /**
     * Default constructor
     *
     * @param tagName {@link String}
     */
    XMLERSElement(String tagName) {
        this.tagName = tagName;
        this.namespace = XMLERSNamespaces.XMLERS;
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
