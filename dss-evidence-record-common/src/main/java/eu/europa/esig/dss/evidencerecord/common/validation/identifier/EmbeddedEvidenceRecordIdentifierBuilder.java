/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
