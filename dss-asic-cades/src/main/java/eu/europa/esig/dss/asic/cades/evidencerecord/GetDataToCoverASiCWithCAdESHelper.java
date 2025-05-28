package eu.europa.esig.dss.asic.cades.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;

import java.util.List;

/**
 * This interface provides the common methods for data extraction to be covered by an evidence record
 *
 */
public interface GetDataToCoverASiCWithCAdESHelper {

    /**
     * Returns a list of documents to be covered by an evidence record
     *
     * NOTE: In CMS/CAdES, only one file can be signed
     *
     * @return {@link DSSDocument} to sign
     */
    List<DSSDocument> getToBeCovered();

}
