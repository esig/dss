package eu.europa.esig.dss.evidencerecord.common.validation;

import java.util.List;

/**
 * Parses an Evidence Record document and produces an ordered list of {@code ArchiveTimeStampChainObject} elements
 *
 */
public interface EvidenceRecordParser {

    /**
     * Parses the Evidence Record object and returns a list of {@code ArchiveTimeStampChainObject}s
     * representing an archive time-stamp sequence
     *
     * @return a list of {@code ArchiveTimeStampChainObject}s
     */
    List<? extends ArchiveTimeStampChainObject> parse();

}
