/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.util.List;

/**
 * Represents an ArchiveTimeStampChain object incorporated within an Evidence Record
 */
public class ArchiveTimeStampChainObject implements EvidenceRecordObject {

    private static final long serialVersionUID = -981112646470456626L;

    /** Digest algorithm used for digest computation of data objects */
    private DigestAlgorithm digestAlgorithm;

    /** List of ordered ArchiveTimeStamp objects */
    private List<? extends ArchiveTimeStampObject> archiveTimeStamps;

    /**
     * Default constructor
     */
    public ArchiveTimeStampChainObject() {
        // empty
    }

    /**
     * Gets DigestAlgorithm used for digest of data objects generation
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Sets DigestAlgorithm used on data objects' digest generation
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     */
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    /**
     * Gets an ordered list of archive time-stamp data objects
     *
     * @return a list of {@link ArchiveTimeStampObject}s
     */
    public List<? extends ArchiveTimeStampObject> getArchiveTimeStamps() {
        return archiveTimeStamps;
    }

    /**
     * Sets an ordered list of archive time-stamp data objects
     *
     * @param archiveTimeStamps a list of {@link ArchiveTimeStampObject}s
     */
    public void setArchiveTimeStamps(List<? extends ArchiveTimeStampObject> archiveTimeStamps) {
        this.archiveTimeStamps = archiveTimeStamps;
    }

}
