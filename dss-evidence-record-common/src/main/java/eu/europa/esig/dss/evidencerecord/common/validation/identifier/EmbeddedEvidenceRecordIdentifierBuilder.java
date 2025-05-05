package eu.europa.esig.dss.evidencerecord.common.validation.identifier;

import eu.europa.esig.dss.spi.validation.evidencerecord.EmbeddedEvidenceRecordHelper;

/**
 * Builds an {@code eu.europa.esig.dss.model.identifier.Identifier}
 * for a {@code eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord} embedded within a signature
 *
 */
public class EmbeddedEvidenceRecordIdentifierBuilder extends EvidenceRecordIdentifierBuilder {

    /** Prefix string for the order of attribute value */
    private static final String ORDER_OF_ATTRIBUTE_PREFIX = "-OOA-";

    /** Prefix string for order within attribute value */
    private static final String ORDER_WITHIN_ATTRIBUTE_PREFIX = "-OWA-";

    /** Contains utilities for processing an embedded evidence record */
    private final EmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper;

    /**
     * Default constructor
     *
     * @param embeddedEvidenceRecordHelper {@link EmbeddedEvidenceRecordHelper}
     */
    public EmbeddedEvidenceRecordIdentifierBuilder(EmbeddedEvidenceRecordHelper embeddedEvidenceRecordHelper) {
        this.embeddedEvidenceRecordHelper = embeddedEvidenceRecordHelper;
    }

    @Override
    protected String getEvidenceRecordPosition() {
        StringBuilder sb = new StringBuilder();
        if (embeddedEvidenceRecordHelper.getMasterSignature() != null) {
            sb.append(embeddedEvidenceRecordHelper.getMasterSignature().getId());
        }
        if (embeddedEvidenceRecordHelper.getEvidenceRecordAttribute() != null) {
            sb.append(embeddedEvidenceRecordHelper.getEvidenceRecordAttribute().getIdentifier().asXmlId());
        }
        if (embeddedEvidenceRecordHelper.getOrderOfAttribute() != null) {
            sb.append(ORDER_OF_ATTRIBUTE_PREFIX);
            sb.append(embeddedEvidenceRecordHelper.getOrderOfAttribute());
        }
        if (embeddedEvidenceRecordHelper.getOrderWithinAttribute() != null) {
            sb.append(ORDER_WITHIN_ATTRIBUTE_PREFIX);
            sb.append(embeddedEvidenceRecordHelper.getOrderWithinAttribute());
        }
        return sb.toString();
    }

}
