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
