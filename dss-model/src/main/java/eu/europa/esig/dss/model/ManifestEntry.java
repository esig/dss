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

import eu.europa.esig.dss.enumerations.MimeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * Defines a references document entry of a ManifestFile
 */
public class ManifestEntry implements Serializable {

	private static final long serialVersionUID = -7997341134695311883L;

	private static final Logger LOG = LoggerFactory.getLogger(ManifestEntry.class);

	/** The reference URI */
	private String uri;

	/** The mimetype of the entry */
	private MimeType mimeType;

	/** The digest of the referenced entry */
	private Digest digest;

	/** NThe matching document, when found */
	private DSSDocument document;

	/**
	 * Defines if the referenced data is found
	 * (used for reference validation)
	 */
	private boolean dataFound;

	/**
	 * Defines if the referenced data is intact (digest matches)
	 * (used for reference validation)
	 */
	private boolean dataIntact;

	/** Defines if it is the root file */
	private boolean rootfile;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ManifestEntry() {
		// empty
	}

	/**
	 * Gets the filename
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Sets the filename
	 *
	 * @param uri {@link String}
	 */
	public void setUri(String uri) {
		this.uri = uri;
	}

	/**
	 * Gets the mimetype
	 *
	 * @return {@link MimeType}
	 */
	public MimeType getMimeType() {
		return mimeType;
	}

	/**
	 * Sets the mimetype
	 *
	 * @param mimeType {@link MimeType}
	 */
	public void setMimeType(MimeType mimeType) {
		this.mimeType = mimeType;
	}

	/**
	 * Gets the manifest entry digest
	 *
	 * @return {@link Digest}
	 */
	public Digest getDigest() {
		return digest;
	}

	/**
	 * Sets the manifest entry digest
	 *
	 * @param digest {@link Digest}
	 */
	public void setDigest(Digest digest) {
		this.digest = digest;
	}

	/**
	 * Sets the name of the corresponding document
	 *
	 * @param documentName {@link String}
	 */
	public void setDocumentName(String documentName) {
		LOG.warn("Use of deprecated method #setDocumentName. Please switch to #setDocument. Current method processing is skipped");
	}

	/**
	 * Gets the corresponding document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getDocument() {
		return document;
	}

	/**
	 * Sets the corresponding document
	 *
	 * @param document {@link DSSDocument}
	 */
	public void setDocument(DSSDocument document) {
		this.document = document;
	}

	/**
	 * Gets if the referenced document has been found
	 *
	 * @return TRUE if the document has been found, FALSE otherwise
	 */
	public boolean isFound() {
		return dataFound;
	}

	/**
	 * Sets if the referenced document has been found
	 *
	 * @param found if the referenced document has been found
	 */
	public void setFound(boolean found) {
		this.dataFound = found;
	}

	/**
	 * Gets if the digest of the reference document matches
	 *
	 * @return TRUE if the digest of the reference document matches, FALSE otherwise
	 */
	public boolean isIntact() {
		return dataIntact;
	}

	/**
	 * Sets if the digest of the reference document matches
	 *
	 * @param intact if the digest of the reference document matches
	 */
	public void setIntact(boolean intact) {
		this.dataIntact = intact;
	}

	/**
	 * Checks if it is a rootfile
	 *
	 * @return TRUE if value of 'Rootfile' set to true, FALSE otherwise
	 */
	public boolean isRootfile() {
		return rootfile;
	}

	/**
	 * Sets if value of 'Rootfile' set to true, FALSE otherwise
	 *
	 * @param rootfile if it is a rootfile
	 */
	public void setRootfile(boolean rootfile) {
		this.rootfile = rootfile;
	}

}
