package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;

/**
 * Creates a new evidence record's filename for the current container type and
 * {@code eu.europa.esig.dss.asic.common.ASiCContent}
 *
 */
public interface ASiCEvidenceRecordFilenameFactory {

    /**
     * Returns a filename for an evidence record file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @param evidenceRecordType {@link EvidenceRecordTypeEnum} type of the evidence record to get a new filename for
     * @return {@link String} evidence record filename
     */
    String getEvidenceRecordFilename(ASiCContent asicContent, EvidenceRecordTypeEnum evidenceRecordType);

    /**
     * Returns a filename for an evidence record's ASIC manifest file to be created
     *
     * @param asicContent {@link ASiCContent} representing a content of an ASiC container
     * @return {@link String} evidence record's manifest filename
     */
    String getEvidenceRecordManifestFilename(ASiCContent asicContent);

}
