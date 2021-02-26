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
package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a parsed Manifest File object
 */
public class ManifestFile {

	/** The DSSDocument represented by the ManifestFile */
	private DSSDocument document;
	
	/** The name of a signature or timestamp associated to the ManifestFile */
	private String signatureFilename;
	
	/** List of entries present in the document */
	private List<ManifestEntry> entries;
	
	/** TRUE if the ManifestFile is associated with a timestamp object, FALSE otherwise */
	private boolean timestampManifest;

	/** TRUE if it is an ASiCArchiveManifest file, FALSE otherwise */
	private boolean archiveManifest;

	/**
	 * Gets the {@code DSSDocument} representing the manifest
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getDocument() {
		return document;
	}

	/**
	 * Sets the manifest document
	 *
	 * @param document {@link DSSDocument}
	 */
	public void setDocument(DSSDocument document) {
		this.document = document;
	}

	/**
	 * Gets the manifest document's filename
	 *
	 * @return {@link String}
	 */
	public String getFilename() {
		return document.getName();
	}

	/**
	 * Gets the signature filename
	 *
	 * @return {@link String}
	 */
	public String getSignatureFilename() {
		return signatureFilename;
	}

	/**
	 * Sets the signature filename
	 *
	 * @param signatureFilename {@link String}
	 */
	public void setSignatureFilename(String signatureFilename) {
		this.signatureFilename = signatureFilename;
	}

	/**
	 * Gets base64 encoded digest string of the manifest document for the given {@code digestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to compute digest
	 * @return {@link String} base64-encoded digest value
	 */
	public String getDigestBase64String(DigestAlgorithm digestAlgorithm) {
		return document.getDigest(digestAlgorithm);
	}

	/**
	 * Gets a list of {@code ManifestEntry}s
	 *
	 * @return a list of {@code ManifestEntry}s
	 */
	public List<ManifestEntry> getEntries() {
		if (entries == null) {
			entries = new ArrayList<>();
		}
		return entries;
	}

	/**
	 * Sets a list of {@code ManifestEntry}s
	 *
	 * @param entries a list of {@code ManifestEntry}s
	 */
	public void setEntries(List<ManifestEntry> entries) {
		this.entries = entries;
	}

	/**
	 * Gets if the manifest is related to a timestamp
	 *
	 * @return TRUE if it is a timestamp's manifest, FALSE otherwise
	 */
	public boolean isTimestampManifest() {
		return timestampManifest;
	}

	/**
	 * Sets if the manifest is related to a timestamp
	 *
	 * @param timestampManifest if it is a timestamp's manifest
	 */
	public void setTimestampManifest(boolean timestampManifest) {
		this.timestampManifest = timestampManifest;
	}

	/**
	 * Gets if the manifest is related to an archive timestamp (ASiC-E with CAdES)
	 *
	 * @return TRUE if it is an archive timestamp's manifest, FALSE otherwise
	 */
	public boolean isArchiveManifest() {
		return archiveManifest;
	}

	/**
	 * Sets if the manifest is related to an archive timestamp (ASiC-E with CAdES)
	 *
	 * @param archiveManifest if it is an archive timestamp's manifest
	 */
	public void setArchiveManifest(boolean archiveManifest) {
		this.archiveManifest = archiveManifest;
	}
	
	/**
	 * Returns a {@link ManifestEntry} with argument Rootfile="true"
	 * @return {@link ManifestEntry} if the rootfile is found, FALSE otherwise
	 */
	public ManifestEntry getRootFile() {
		for (ManifestEntry entry : getEntries()) {
			if (entry.isRootfile()) {
				return entry;
			}
		}
		return null;
	}

}
