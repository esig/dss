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

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Contains information about an ASiC container
 */
public class ContainerInfo {

	/** ASiC container type */
	private ASiCContainerType containerType;

	/** The ZIP comment of the archive */
	private String zipComment;

	/** The mimetype file content */
	private String mimeTypeContent;

	/** The list of signed document filenames */
	private List<String> signedDocumentFilenames;

	/** The list of embedded manifest files */
	private List<ManifestFile> manifestFiles;

	/**
	 * Default constructor instantiating object with null values
	 */
	public ContainerInfo() {
		// empty
	}

	/**
	 * Gets the {@code ASiCContainerType}
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return containerType;
	}

	/**
	 * Sets the {@code ASiCContainerType}
	 *
	 * @param containerType {@link ASiCContainerType}
	 */
	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	/**
	 * Gets the zip comment
	 *
	 * @return {@link String}
	 */
	public String getZipComment() {
		return zipComment;
	}

	/**
	 * Sets the zip comment
	 *
	 * @param zipComment {@link String}
	 */
	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

	/**
	 * Gets mimetype file content
	 *
	 * @return {@link String}
	 */
	public String getMimeTypeContent() {
		return mimeTypeContent;
	}

	/**
	 * Sets mimetype file content
	 *
	 * @param mimeTypeContent {@link String}
	 */
	public void setMimeTypeContent(String mimeTypeContent) {
		this.mimeTypeContent = mimeTypeContent;
	}

	/**
	 * Returns if the mimetype file present
	 *
	 * @return TRUE if the mimetype present, FALSE otherwise
	 */
	public boolean isMimeTypeFilePresent() {
		return Utils.isStringNotEmpty(mimeTypeContent);
	}

	/**
	 * Returns a list of signed document filenames
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getSignedDocumentFilenames() {
		return signedDocumentFilenames;
	}

	/**
	 * Sets signed document filenames
	 *
	 * @param signedDocumentFilenames a list of {@link String}s
	 */
	public void setSignedDocumentFilenames(List<String> signedDocumentFilenames) {
		this.signedDocumentFilenames = signedDocumentFilenames;
	}

	/**
	 * Gets a list of manifest files
	 *
	 * @return a list of {@link ManifestFile}s
	 */
	public List<ManifestFile> getManifestFiles() {
		return manifestFiles;
	}

	/**
	 * Sets a list of manifest files
	 *
	 * @param manifestFiles a list of manifest files
	 */
	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}

}
