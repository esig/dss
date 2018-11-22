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

import java.util.List;

import eu.europa.esig.dss.ASiCContainerType;

public class ContainerInfo {

	private ASiCContainerType containerType;
	private String zipComment;
	private boolean mimeTypeFilePresent;
	private String mimeTypeContent;

	private List<String> signedDocumentFilenames;
	private List<ManifestFile> manifestFiles;

	public ASiCContainerType getContainerType() {
		return containerType;
	}

	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	public String getZipComment() {
		return zipComment;
	}

	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

	public boolean isMimeTypeFilePresent() {
		return mimeTypeFilePresent;
	}

	public void setMimeTypeFilePresent(boolean mimeTypeFilePresent) {
		this.mimeTypeFilePresent = mimeTypeFilePresent;
	}

	public String getMimeTypeContent() {
		return mimeTypeContent;
	}

	public void setMimeTypeContent(String mimeTypeContent) {
		this.mimeTypeContent = mimeTypeContent;
	}

	public List<String> getSignedDocumentFilenames() {
		return signedDocumentFilenames;
	}

	public void setSignedDocumentFilenames(List<String> signedDocumentFilenames) {
		this.signedDocumentFilenames = signedDocumentFilenames;
	}

	public List<ManifestFile> getManifestFiles() {
		return manifestFiles;
	}

	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}

}
