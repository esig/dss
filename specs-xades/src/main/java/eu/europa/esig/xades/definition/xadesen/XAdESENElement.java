package eu.europa.esig.xades.definition.xadesen;

import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.xades.definition.XAdESNamespace;

public enum XAdESENElement implements DSSElement {

    /** Defines ASN1EvidenceRecord */
    ASN1_EVIDENCE_RECORD("ASN1EvidenceRecord"),

    /** Defines XML EvidenceRecord */
    EVIDENCE_RECORD("EvidenceRecord"),

    /** Defines an EvidenceRecord container */
    SEALING_EVIDENCE_RECORDS("SealingEvidenceRecords");

    /** Namespace */
    private final DSSNamespace namespace;

    /** The tag name */
    private final String tagName;

    /**
     * Default constructor
     *
     * @param tagName {@link String}
     */
    XAdESENElement(String tagName) {
        this.tagName = tagName;
        this.namespace = XAdESNamespace.XADES_EN;
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
