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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Parameters defining the configuration for creation of an ASiC container containing an evidence record document
 *
 */
public class ASiCContainerEvidenceRecordParameters extends ASiCParameters {

    private static final long serialVersionUID = 7880198032684158062L;

    /** ASiC evidence record manifest file to be added within the container */
    private DSSDocument asicEvidenceRecordManifest;

    /**
     * Default constructor
     */
    public ASiCContainerEvidenceRecordParameters() {
        // empty
    }

    /**
     * Gets ASiCEvidenceRecordManifest file to be added within the container
     *
     * @return {@link DSSDocument}
     */
    public DSSDocument getAsicEvidenceRecordManifest() {
        return asicEvidenceRecordManifest;
    }

    /**
     * (Optional) Sets a custom ASiCEvidenceRecordManifest to be added within the container.
     * When defined, the current manifest file will be used for the evidence record incorporation.
     * When not provided, application will create a new ASiCEvidenceRecordManifest based
     * on the objects covered by the evidence record.
     * The filename of the manifest file will be taken from the document name.
     * The filename of the evidence record document will be taken from the manifest signature reference.
     *
     * @param asicEvidenceRecordManifest {@link DSSDocument} representing a valid ASiCEvidenceRecordManifest file
     */
    public void setAsicEvidenceRecordManifest(DSSDocument asicEvidenceRecordManifest) {
        this.asicEvidenceRecordManifest = asicEvidenceRecordManifest;
    }

}
