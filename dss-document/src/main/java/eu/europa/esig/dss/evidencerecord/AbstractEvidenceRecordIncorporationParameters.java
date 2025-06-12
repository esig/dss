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
package eu.europa.esig.dss.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableEvidenceRecordIncorporationParameters;

import java.util.List;

/**
 * Contains parameters used on Evidence Record incorporation within an existing signature
 *
 */
public abstract class AbstractEvidenceRecordIncorporationParameters implements SerializableEvidenceRecordIncorporationParameters {

    private static final long serialVersionUID = 8520066550031111847L;

    /**
     * Identifier of a signature to include the evidence record into
     */
    private String signatureId;

    /**
     * The detached documents signed by a signature
     */
    private List<DSSDocument> detachedContents;

    /**
     * Defines whether the new evidence-record shall be added to the last available evidence-record attribute,
     * when present. Otherwise, the hash will be computed based on the whole document content (default behavior).
     */
    private boolean parallelEvidenceRecord;

    /**
     * Default constructor
     */
    protected AbstractEvidenceRecordIncorporationParameters() {
        // empty
    }

    @Override
    public String getSignatureId() {
        return signatureId;
    }

    @Override
    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    @Override
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    @Override
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    @Override
    public boolean isParallelEvidenceRecord() {
        return parallelEvidenceRecord;
    }

    @Override
    public void setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        this.parallelEvidenceRecord = parallelEvidenceRecord;
    }

}
