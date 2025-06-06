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

import java.io.Serializable;
import java.util.List;

/**
 * Contains parameters used on Evidence Record incorporation within an existing signature
 *
 */
public abstract class AbstractEvidenceRecordIncorporationParameters implements Serializable {

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

    /**
     * Gets an identifier of signature to include the evidence record into
     *
     * @return {@link String}
     */
    public String getSignatureId() {
        return signatureId;
    }

    /**
     * Sets an identifier of signature to include the evidence record into.
     * When a document with a single signature is provided, the value can be set to null.
     * Otherwise, the signature with the given identifier shall be found in order to perform the operation.
     *
     * @param signatureId {@link String}
     */
    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    /**
     * Gets detached documents signed by a signature
     *
     * @return a list of {@link DSSDocument}s
     */
    public List<DSSDocument> getDetachedContents() {
        return detachedContents;
    }

    /**
     * Sets detached documents signed by a signature
     *
     * @param detachedContents a list of {@link DSSDocument}s
     */
    public void setDetachedContents(List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    /**
     * Gets whether the evidence record should be incorporated within an existing (latest) evidence-record unsigned property,
     * when available. Otherwise, a new evidence record attribute is to be created for incorporation of the evidence record.
     *
     * @return whether the evidence record should be included in the existing (latest) evidence-record unsigned property
     */
    public boolean isParallelEvidenceRecord() {
        return parallelEvidenceRecord;
    }

    /**
     * Sets whether the evidence record should be incorporated within an existing (latest) evidence-record unsigned property,
     * when available. Otherwise, a new evidence record attribute is to be created for incorporation of the evidence record.
     * <p>
     * Default : FALSE (a new evidence record unsigned property is to be created)
     *
     * @param parallelEvidenceRecord whether the evidence record should be included in
     *                               the existing (latest) evidence-record unsigned property
     */
    public void setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        this.parallelEvidenceRecord = parallelEvidenceRecord;
    }

}
