package eu.europa.esig.xmlers.definition;

import eu.europa.esig.dss.jaxb.common.definition.AbstractPath;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;

/**
 * XMLERS Paths
 */
public class XMLERSPath extends AbstractPath {

    /**
     * Default constructor
     */
    public XMLERSPath() {
        // empty
    }

    /**
     * "./ers:EvidenceRecord"
     */
    public static final String EVIDENCE_RECORD_PATH = fromCurrentPosition(XMLERSElement.EVIDENCE_RECORD);

    /**
     * "./ers:ArchiveTimeStampSequence"
     */
    public static final String ARCHIVE_TIME_STAMP_SEQUENCE_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP_SEQUENCE);

    /**
     * "./ers:ArchiveTimeStampSequence/ers:ArchiveTimeStampChain"
     */
    public static final String ARCHIVE_TIME_STAMP_CHAIN_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP_SEQUENCE, XMLERSElement.ARCHIVE_TIME_STAMP_CHAIN);

    /**
     * "./ers:ArchiveTimeStamp"
     */
    public static final String ARCHIVE_TIME_STAMP_PATH = fromCurrentPosition(XMLERSElement.ARCHIVE_TIME_STAMP);

    /**
     * "./ers:DigestMethod"
     */
    public static final String DIGEST_METHOD_PATH = fromCurrentPosition(XMLERSElement.DIGEST_METHOD);

    /**
     * "./ers:CanonicalizationMethod"
     */
    public static final String CANONICALIZATION_METHOD_PATH = fromCurrentPosition(XMLERSElement.CANONICALIZATION_METHOD);

    /**
     * "./ers:HashTree/ers:Sequence"
     */
    public static final String HASH_TREE_SEQUENCE_PATH = fromCurrentPosition(XMLERSElement.HASH_TREE, XMLERSElement.SEQUENCE);

    /**
     * "./ers:DigestValue"
     */
    public static final String DIGEST_VALUE_PATH = fromCurrentPosition(XMLERSElement.DIGEST_VALUE);

    /**
     * "./ers:TimeStamp"
     */
    public static final String TIME_STAMP_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP);

    /**
     * "./ers:TimeStamp/ers:TimeStampToken"
     */
    public static final String TIME_STAMP_TOKEN_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP, XMLERSElement.TIME_STAMP_TOKEN);

    /**
     * "./ers:TimeStamp/ers:CryptographicInformationList/ers:CryptographicInformation"
     */
    public static final String CRYPTOGRAPHIC_INFORMATION_PATH = fromCurrentPosition(XMLERSElement.TIME_STAMP, XMLERSElement.CRYPTOGRAPHIC_INFORMATION_LIST, XMLERSElement.CRYPTOGRAPHIC_INFORMATION);

    /**
     * Returns a namespace of the XMLERS paths
     *
     * @return {@link DSSNamespace}
     */
    public DSSNamespace getNamespace() {
        return XMLERSNamespace.XMLERS;
    }

}
