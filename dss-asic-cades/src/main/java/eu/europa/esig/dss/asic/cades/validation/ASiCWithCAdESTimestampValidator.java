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
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;

import java.util.List;

/**
 * The abstract validator for an ASiC with CAdES timestamp
 */
public class ASiCWithCAdESTimestampValidator extends DetachedTimestampValidator {

	/** A list of original documents present in the container */
	private List<DSSDocument> originalDocuments;

	/** A list of package.zip embedded documents, when applicable */
	private List<DSSDocument> archiveDocuments;

	/** Defines the archive timestamp type */
	private ArchiveTimestampType archiveTimestampType;

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

	/**
	 * Sets the archive timestamp type
	 *
	 * @param archiveTimestampType {@link ArchiveTimestampType}
	 */
	public void setArchiveTimestampType(ArchiveTimestampType archiveTimestampType) {
		this.archiveTimestampType = archiveTimestampType;
	}

	@Override
	protected TimestampToken createTimestampToken() {
		TimestampToken timestamp = super.createTimestampToken();
		if (manifestFile != null) {
			timestamp.setManifestFile(manifestFile);
		}
		if (archiveTimestampType != null) {
			timestamp.setArchiveTimestampType(archiveTimestampType);
		}
		return timestamp;
	}

	@Override
	protected boolean isTimestampCoveredByEvidenceRecord(TimestampToken timestampToken, EvidenceRecord evidenceRecord) {
		ManifestFile erManifestFile = evidenceRecord.getManifestFile();
		if (erManifestFile == null) {
			// detached ER, covers all content
			return true;
		}
		for (ManifestEntry entry : erManifestFile.getEntries()) {
			if (timestampToken.getFileName() != null && timestampToken.getFileName().equals(entry.getFileName())) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected List<SignatureScope> getTimestampScopes(TimestampToken timestampToken) {
		ASiCWithCAdESTimestampScopeFinder timestampScopeFinder = new ASiCWithCAdESTimestampScopeFinder();
		timestampScopeFinder.setContainerDocuments(originalDocuments);
		timestampScopeFinder.setArchiveDocuments(archiveDocuments);
		timestampScopeFinder.setTimestampedData(getTimestampedData());
		return timestampScopeFinder.findTimestampScope(timestampToken);
	}

	@Override
	protected boolean addReference(SignatureScope signatureScope) {
		String fileName = signatureScope.getDocumentName();
		return fileName == null || (!ASiCUtils.isSignature(fileName) && !ASiCUtils.isTimestamp(fileName) && !ASiCUtils.isEvidenceRecord(fileName));
	}

}
