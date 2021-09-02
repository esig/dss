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
package eu.europa.esig.dss.asic.cades.validation;

import eu.europa.esig.dss.asic.cades.validation.scope.ASiCWithCAdESTimestampScopeFinder;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.scope.DetachedTimestampScopeFinder;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.List;

/**
 * The abstract validator for an ASiC with CAdES timestamp
 */
public class ASiCWithCAdESTimestampValidator extends DetachedTimestampValidator {

	/** A list of original documents present in the container */
	private List<DSSDocument> originalDocuments;

	/** A list of package.zip embedded documents, when applicable */
	private List<DSSDocument> archiveDocuments;

	/**
	 * Default constructor
	 *
	 * @param timestamp
	 *            {@link DSSDocument} the timestamp document file
	 */
	public ASiCWithCAdESTimestampValidator(DSSDocument timestamp) {
		super(timestamp);
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
		super(timestamp, type);
	}

	/**
	 * Returns the covered {@code ManifestFile}
	 *
	 * @return {@link ManifestFile}
	 */
	public ManifestFile getCoveredManifest() {
		return manifestFile;
	}

	/**
	 * Sets the original documents present in the ASiC container
	 *
	 * @param originalDocuments a list of {@link DSSDocument}s
	 */
	public void setOriginalDocuments(List<DSSDocument> originalDocuments) {
		this.originalDocuments = originalDocuments;
	}

	/**
	 * Sets the document embedded inside package.zip, when applicable
	 *
	 * @param archiveDocuments a list of {@link DSSDocument}s
	 */
	public void setArchiveDocuments(List<DSSDocument> archiveDocuments) {
		this.archiveDocuments = archiveDocuments;
	}

	@Override
	protected TimestampToken createTimestampToken() {
		TimestampToken timestamp = super.createTimestampToken();
		if (manifestFile != null) {
			timestamp.setManifestFile(manifestFile);
		}
		if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampType)) {
			timestamp.setArchiveTimestampType(ArchiveTimestampType.CAdES_DETACHED);
		}
		return timestamp;
	}

	@Override
	protected ASiCWithCAdESTimestampScopeFinder getTimestampScopeFinder() {
		return new ASiCWithCAdESTimestampScopeFinder();
	}

	@Override
	protected void prepareDetachedTimestampScopeFinder(DetachedTimestampScopeFinder timestampScopeFinder) {
		super.prepareDetachedTimestampScopeFinder(timestampScopeFinder);

		ASiCWithCAdESTimestampScopeFinder asicWithCAdESTimestampScopeFinder = (ASiCWithCAdESTimestampScopeFinder) timestampScopeFinder;
		asicWithCAdESTimestampScopeFinder.setContainerDocuments(originalDocuments);
		asicWithCAdESTimestampScopeFinder.setArchiveDocuments(archiveDocuments);
	}

	@Override
	protected boolean addReference(SignatureScope signatureScope) {
		String fileName = signatureScope.getName();
		return fileName == null || (!ASiCUtils.isSignature(fileName) && !ASiCUtils.isTimestamp(fileName));
	}

}
