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
package eu.europa.esig.dss.asic;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;

public class ASiCExtractResult {

	private String zipComment;
	private DSSDocument mimeTypeDocument;
	private List<DSSDocument> signatureDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> manifestDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> archiveManifestDocuments = new ArrayList<DSSDocument>(); // ASiC with CAdES
	private List<DSSDocument> timestampDocuments = new ArrayList<DSSDocument>(); // ASiC with CAdES
	private List<DSSDocument> signedDocuments = new ArrayList<DSSDocument>();
	private List<DSSDocument> unsupportedDocuments = new ArrayList<DSSDocument>();

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

	public List<DSSDocument> getSignedDocuments() {
		return signedDocuments;
	}

	public void setSignedDocuments(List<DSSDocument> signedDocuments) {
		this.signedDocuments = signedDocuments;
	}

	public List<DSSDocument> getUnsupportedDocuments() {
		return unsupportedDocuments;
	}

	public void setUnsupportedDocuments(List<DSSDocument> unsupportedDocuments) {
		this.unsupportedDocuments = unsupportedDocuments;
	}

}
