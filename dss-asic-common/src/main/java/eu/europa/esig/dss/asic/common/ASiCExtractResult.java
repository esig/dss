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
package eu.europa.esig.dss.asic.common;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCExtractResult {

	private String zipComment;
	private DSSDocument mimeTypeDocument;
	private List<DSSDocument> allDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> originalDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> signatureDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> manifestDocuments = new ArrayList<DSSDocument>();
	private List<ManifestFile> manifestFiles = new ArrayList<ManifestFile>();
	private List<DSSDocument> archiveManifestDocuments = new ArrayList<DSSDocument>(); // ASiC with CAdES
	private List<DSSDocument> timestampDocuments = new ArrayList<DSSDocument>(); // ASiC with CAdES
	private List<DSSDocument> unsupportedDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> containerDocuments = new ArrayList<DSSDocument>(); // for ASiC signatures
	private DSSDocument rootContainer; // For OpenDocument

	public String getZipComment() {
		return zipComment;
	}

	public void setZipComment(String zipComment) {
		this.zipComment = zipComment;
	}

	public DSSDocument getMimeTypeDocument() {
		return mimeTypeDocument;
	}

	public void setMimeTypeDocument(DSSDocument mimeTypeDocument) {
		this.mimeTypeDocument = mimeTypeDocument;
	}

	public List<DSSDocument> getSignatureDocuments() {
		return signatureDocuments;
	}

	public void setSignatureDocuments(List<DSSDocument> signatureDocuments) {
		this.signatureDocuments = signatureDocuments;
	}

	public List<DSSDocument> getManifestDocuments() {
		return manifestDocuments;
	}

	public void setManifestDocuments(List<DSSDocument> manifestDocuments) {
		this.manifestDocuments = manifestDocuments;
	}
	
	public List<ManifestFile> getManifestFiles() {
		return manifestFiles;
	}
	
	public void setManifestFiles(List<ManifestFile> manifestFiles) {
		this.manifestFiles = manifestFiles;
	}

	public List<DSSDocument> getArchiveManifestDocuments() {
		return archiveManifestDocuments;
	}

	public void setArchiveManifestDocuments(List<DSSDocument> archiveManifestDocuments) {
		this.archiveManifestDocuments = archiveManifestDocuments;
	}

	public List<DSSDocument> getTimestampDocuments() {
		return timestampDocuments;
	}

	public void setTimestampDocuments(List<DSSDocument> timestampDocuments) {
		this.timestampDocuments = timestampDocuments;
	}

	public List<DSSDocument> getAllDocuments() {
		return allDocuments;
	}

	public void setAllDocuments(List<DSSDocument> allDocuments) {
		this.allDocuments = allDocuments;
	}

	public List<DSSDocument> getOriginalDocuments() {
		return originalDocuments;
	}

	public void setOriginalDocuments(List<DSSDocument> originalDocuments) {
		this.originalDocuments = originalDocuments;
	}

	public List<DSSDocument> getUnsupportedDocuments() {
		return unsupportedDocuments;
	}

	public void setUnsupportedDocuments(List<DSSDocument> unsupportedDocuments) {
		this.unsupportedDocuments = unsupportedDocuments;
	}
	
	public List<DSSDocument> getContainerDocuments() {
		return containerDocuments;
	}
	
	public void setContainerDocuments(List<DSSDocument> containerDocuments) {
		this.containerDocuments = containerDocuments;
	}
	
	public DSSDocument getRootContainer() {
		return rootContainer;
	}

	public void setRootContainer(DSSDocument rootContainer) {
		this.rootContainer = rootContainer;
	}
	
	/**
	 * Returns a list of all found manifest documents
	 * 
	 * @return list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		List<DSSDocument> allManifestsList = new ArrayList<DSSDocument>();
		allManifestsList.addAll(getManifestDocuments());
		allManifestsList.addAll(getArchiveManifestDocuments());
		return allManifestsList;
	}

	/**
	 * Returns list of documents covered by the {@code timestamp}
	 * @param timestamp {@link DSSDocument}
	 * @return list of timestamped {@link DSSDocument} documents
	 */
	public List<DSSDocument> getTimestampedDocuments(DSSDocument timestamp) {
		List<DSSDocument> timestampedDocuments = new ArrayList<DSSDocument>();
		timestampedDocuments.addAll(getOriginalDocuments());
		timestampedDocuments.addAll(getManifestDocuments());
		timestampedDocuments.addAll(getSignatureDocuments());
		timestampedDocuments.addAll(getArchiveManifestDocuments());
		timestampedDocuments.add(getMimeTypeDocument());
		for (DSSDocument timestampDocument : getTimestampDocuments()) {
			if (timestampDocument.getName().compareTo(timestamp.getName()) < 0) {
				timestampedDocuments.add(timestampDocument);
			}
		}
		return timestampedDocuments;
	}

}
