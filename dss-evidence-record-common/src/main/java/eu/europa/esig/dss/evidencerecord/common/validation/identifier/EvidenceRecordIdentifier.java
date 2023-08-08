package eu.europa.esig.dss.evidencerecord.common.validation.identifier;

import eu.europa.esig.dss.model.identifier.MultipleDigestIdentifier;

/**
 * Creates unique identifier for an evidence record
 *
 */
public class EvidenceRecordIdentifier extends MultipleDigestIdentifier {

    private static final long serialVersionUID = 6359543697190790257L;

    /**
     * Default constructor
     *
     * @param binaries token binaries
     */
    protected EvidenceRecordIdentifier(byte[] binaries) {
        super("ER-", binaries);
    }

}
