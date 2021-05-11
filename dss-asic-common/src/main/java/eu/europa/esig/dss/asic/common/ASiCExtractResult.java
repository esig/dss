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

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;

import java.util.ArrayList;
import java.util.List;

/**
 * Contains grouped documents representing an ASiC container extaction result
 */
public class ASiCExtractResult {

	/** The original ASiC container */
	private DSSDocument asicContainer;

	/** The container type */
	private ASiCContainerType containerType;

	/** The zip comment */
	private String zipComment;

	/** The mimetype document */
	private DSSDocument mimeTypeDocument;

	/** The list of all documents embedded into the container */
	private List<DSSDocument> allDocuments = new ArrayList<>();

	/** The list of originally signed documents embedded into the container */
	private List<DSSDocument> signedDocuments = new ArrayList<>();

	/** The list of signature documents embedded into the container */
	private List<DSSDocument> signatureDocuments = new ArrayList<>();

	/** The list of manifest documents embedded into the container */
	private List<DSSDocument> manifestDocuments = new ArrayList<>();

	/** The list of archive manifest documents embedded into the container (ASiC with CAdES) */
	private List<DSSDocument> archiveManifestDocuments = new ArrayList<>();

	/** The list of timestamp documents embedded into the container (ASiC with CAdES) */
	private List<DSSDocument> timestampDocuments = new ArrayList<>();

	/** The list of unsupported documents embedded into the container */
	private List<DSSDocument> unsupportedDocuments = new ArrayList<>();

	/** The list of "package.zip" documents (ASiC-S) */
	private List<DSSDocument> containerDocuments = new ArrayList<>();

	/** The root container document (for OpenDocument) */
	private DSSDocument rootContainer;

	/**
	 * Gets the original ASiC container
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getAsicContainer() {
		return asicContainer;
	}

	/**
	 * Sets the original ASiC container
	 *
	 * @param asicContainer {@link DSSDocument}
	 */
	public void setAsicContainer(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	/**
	 * Gets the container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getContainerType() {
		return containerType;
	}

	/**
	 * Sets the container type
	 *
	 * @param containerType {@link ASiCContainerType}
	 */
	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	/**
	 * Gets the zip comment
	 *
	 * @return {@link String} zip comment
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
	 * Gets mimetype document
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getMimeTypeDocument() {
		return mimeTypeDocument;
	}

	/**
	 * Sets mimetype document
	 *
	 * @param mimeTypeDocument {@link DSSDocument}
	 */
	public void setMimeTypeDocument(DSSDocument mimeTypeDocument) {
		this.mimeTypeDocument = mimeTypeDocument;
	}

	/**
	 * Gets signature documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignatureDocuments() {
		return signatureDocuments;
	}

	/**
	 * Sets signature documents
	 *
	 * @param signatureDocuments a list of {@link DSSDocument}s
	 */
	public void setSignatureDocuments(List<DSSDocument> signatureDocuments) {
		this.signatureDocuments = signatureDocuments;
	}

	/**
	 * Gets manifest documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getManifestDocuments() {
		return manifestDocuments;
	}

	/**
	 * Sets manifest documents
	 *
	 * @param manifestDocuments a list of {@link DSSDocument}s
	 */
	public void setManifestDocuments(List<DSSDocument> manifestDocuments) {
		this.manifestDocuments = manifestDocuments;
	}

	/**
	 * Gets archive manifest documents (ASiC with CAdES only)
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getArchiveManifestDocuments() {
		return archiveManifestDocuments;
	}

	/**
	 * Sets archive manifest documents (ASiC with CAdES only)
	 *
	 * @param archiveManifestDocuments a list of {@link DSSDocument}s
	 */
	public void setArchiveManifestDocuments(List<DSSDocument> archiveManifestDocuments) {
		this.archiveManifestDocuments = archiveManifestDocuments;
	}

	/**
	 * Gets timestamp documents (ASiC with CAdES only)
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getTimestampDocuments() {
		return timestampDocuments;
	}

	/**
	 * Sets timestamp documents (ASiC with CAdES only)
	 *
	 * @param timestampDocuments a list of {@link DSSDocument}s
	 */
	public void setTimestampDocuments(List<DSSDocument> timestampDocuments) {
		this.timestampDocuments = timestampDocuments;
	}

	/**
	 * Gets all documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllDocuments() {
		return allDocuments;
	}

	/**
	 * Sets all documents
	 *
	 * @param allDocuments a list of {@link DSSDocument}s
	 */
	public void setAllDocuments(List<DSSDocument> allDocuments) {
		this.allDocuments = allDocuments;
	}

	/**
	 * Gets signed documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	/**
	 * Sets signed documents
	 *
	 * @param signedDocuments a list of {@link DSSDocument}s
	 */
	public void setSignedDocuments(List<DSSDocument> signedDocuments) {
		this.signedDocuments = signedDocuments;
	}

	/**
	 * Gets unsupported documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getUnsupportedDocuments() {
		return unsupportedDocuments;
	}

	/**
	 * Sets unsupported documents
	 *
	 * @param unsupportedDocuments a list of {@link DSSDocument}s
	 */
	public void setUnsupportedDocuments(List<DSSDocument> unsupportedDocuments) {
		this.unsupportedDocuments = unsupportedDocuments;
	}

	/**
	 * Gets "package.zip" documents
	 *
	 * @return a list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getContainerDocuments() {
		return containerDocuments;
	}

	/**
	 * Sets package.zip" documents
	 *
	 * @param containerDocuments a list of {@link DSSDocument}s
	 */
	public void setContainerDocuments(List<DSSDocument> containerDocuments) {
		this.containerDocuments = containerDocuments;
	}

	/**
	 * Gets the root container (OpenDocument)
	 *
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getRootContainer() {
		return rootContainer;
	}

	/**
	 * Sets the root container (OpenDocument)
	 *
	 * @param rootContainer {@link DSSDocument}
	 */
	public void setRootContainer(DSSDocument rootContainer) {
		this.rootContainer = rootContainer;
	}
	
	/**
	 * Returns a list of all found manifest documents
	 * 
	 * @return list of {@link DSSDocument}s
	 */
	public List<DSSDocument> getAllManifestDocuments() {
		List<DSSDocument> allManifestsList = new ArrayList<>();
		allManifestsList.addAll(getManifestDocuments());
		allManifestsList.addAll(getArchiveManifestDocuments());
		return allManifestsList;
	}

}
