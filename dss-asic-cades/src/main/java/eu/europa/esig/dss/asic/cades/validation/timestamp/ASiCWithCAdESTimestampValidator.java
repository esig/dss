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
package eu.europa.esig.dss.asic.cades.validation.timestamp;

import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;

import java.util.List;

/**
 * The abstract validator for an ASiC with CAdES timestamp
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class ASiCWithCAdESTimestampValidator extends DetachedTimestampValidator {

    /**
     * Default constructor
     *
     * @param timestamp
     *            {@link DSSDocument} the timestamp document file
     */
    public ASiCWithCAdESTimestampValidator(DSSDocument timestamp) {
        super(new ASiCWithCAdESTimestampAnalyzer(timestamp));
    }

    /**
     * Default constructor with a timestamp type
     *
     * @param timestamp
     *            {@link DSSDocument} the timestamp document file
     * @param type
     *            {@link TimestampType} type of the timestamp
     */
    public ASiCWithCAdESTimestampValidator(DSSDocument timestamp, TimestampType type) {
        super(new ASiCWithCAdESTimestampAnalyzer(timestamp, type));
    }

    @Override
    public ASiCWithCAdESTimestampAnalyzer getDocumentAnalyzer() {
        return (ASiCWithCAdESTimestampAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * Returns the covered {@code ManifestFile}
     *
     * @return {@link ManifestFile}
     */
    public ManifestFile getCoveredManifest() {
        return getDocumentAnalyzer().getCoveredManifest();
    }

    /**
     * Sets the original documents present in the ASiC container
     *
     * @param originalDocuments a list of {@link DSSDocument}s
     */
    public void setOriginalDocuments(List<DSSDocument> originalDocuments) {
        getDocumentAnalyzer().setOriginalDocuments(originalDocuments);
    }

    /**
     * Sets the document embedded inside package.zip, when applicable
     *
     * @param archiveDocuments a list of {@link DSSDocument}s
     */
    public void setArchiveDocuments(List<DSSDocument> archiveDocuments) {
        getDocumentAnalyzer().setArchiveDocuments(archiveDocuments);
    }

    /**
     * Sets the archive timestamp type
     *
     * @param archiveTimestampType {@link ArchiveTimestampType}
     */
    public void setArchiveTimestampType(ArchiveTimestampType archiveTimestampType) {
        getDocumentAnalyzer().setArchiveTimestampType(archiveTimestampType);
    }

}