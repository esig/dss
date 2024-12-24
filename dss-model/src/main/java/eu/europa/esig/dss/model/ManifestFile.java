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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.ASiCManifestTypeEnum;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a parsed Manifest File object
 */
public class ManifestFile implements Serializable {

	private static final long serialVersionUID = -5971045309587760817L;

	/** The DSSDocument represented by the ManifestFile */
	private DSSDocument document;
	
	/** The name of a signature or timestamp associated to the ManifestFile */
	private String signatureFilename;
	
	/** List of entries present in the document */
	private List<ManifestEntry> entries;
	
	/** Defines the type of the manifest document */
	private ASiCManifestTypeEnum manifestType;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ManifestFile() {
		// empty
	}

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
	 * Gets digest value of the manifest document for the given {@code digestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to compute digest
	 * @return byte array representing the digest value
	 */
	public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
		return document.getDigestValue(digestAlgorithm);
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
	 * Gets a type of the ASiC Manifest file
	 *
	 * @return {@link ASiCManifestTypeEnum}
	 */
	public ASiCManifestTypeEnum getManifestType() {
		return manifestType;
	}

	/**
	 * Sets a type of the ASiC Manifest file
	 *
	 * @param manifestType {@link ASiCManifestTypeEnum}
	 */
	public void setManifestType(ASiCManifestTypeEnum manifestType) {
		this.manifestType = manifestType;
	}
	
	/**
	 * Returns a {@link ManifestEntry} with argument Rootfile="true"
	 *
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

	/**
	 * Checks if the document with {@code documentName} is covered by the Manifest
	 *
	 * @param documentName {@link String} to check
	 * @return TRUE if the document with the given name is covered, FALSE otherwise
	 */
	public boolean isDocumentCovered(String documentName) {
		if (documentName != null && documentName.length() > 0) {
			for (ManifestEntry entry : getEntries()) {
				if (documentName.equals(entry.getUri())) {
					return true;
				}
			}
		}
		return false;
	}

}
