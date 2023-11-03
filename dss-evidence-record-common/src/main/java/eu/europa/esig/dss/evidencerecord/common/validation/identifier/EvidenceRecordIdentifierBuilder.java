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
package eu.europa.esig.dss.evidencerecord.common.validation.identifier;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Builds an {@code eu.europa.esig.dss.model.identifier.Identifier}
 * for an {@code eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord}
 *
 */
public class EvidenceRecordIdentifierBuilder {

    /** Evidence record to build identifier for */
    private final DefaultEvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link DefaultEvidenceRecord}
     */
    public EvidenceRecordIdentifierBuilder(DefaultEvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Builds an {@code EvidenceRecordIdentifier}
     *
     * @return {@link EvidenceRecordIdentifier}
     */
    public EvidenceRecordIdentifier build() {
        return new EvidenceRecordIdentifier(buildBinaries());
    }

    /**
     * Builds unique binary data describing the signature object
     *
     * @return a byte array
     */
    protected byte[] buildBinaries() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
            ArchiveTimeStampChainObject archiveTimeStampChainObject = archiveTimeStampSequence.get(0);
            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChainObject.getArchiveTimeStamps();
            ArchiveTimeStampObject archiveTimeStampObject = archiveTimeStamps.get(0);

            List<? extends DigestValueGroup> hashTree = archiveTimeStampObject.getHashTree();
            if (Utils.isCollectionNotEmpty(hashTree)) {
                for (DigestValueGroup digestValueGroup : hashTree) {
                    List<byte[]> digestValues = digestValueGroup.getDigestValues();
                    if (Utils.isCollectionNotEmpty(digestValues)) {
                        for (byte[] binaries : digestValues) {
                            baos.write(binaries);
                        }
                    }
                }
            }
            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            if (Utils.isCollectionNotEmpty(timestamps)) {
                // first time-stamp identifies the signature
                baos.write(timestamps.get(0).getEncoded());
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
