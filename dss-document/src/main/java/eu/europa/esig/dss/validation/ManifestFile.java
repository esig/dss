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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;

public class ManifestFile {

	private DSSDocument document;
	private String signatureFilename;
	private List<ManifestEntry> entries;
	private boolean archiveManifest;

	public void setDocument(DSSDocument document) {
		this.document = document;
	}

	public String getFilename() {
		return document.getName();
	}

	public String getSignatureFilename() {
		return signatureFilename;
	}

	public void setSignatureFilename(String signatureFilename) {
		this.signatureFilename = signatureFilename;
	}
	
	public String getDigestBase64String(DigestAlgorithm digestAlgorithm) {
		return document.getDigest(digestAlgorithm);
	}

	public List<ManifestEntry> getEntries() {
		if (entries == null) {
			entries = new ArrayList<ManifestEntry>();
		}
		return entries;
	}

	public void setEntries(List<ManifestEntry> entries) {
		this.entries = entries;
	}
	
	public boolean isArchiveManifest() {
		return archiveManifest;
	}

	public void setArchiveManifest(boolean archiveManifest) {
		this.archiveManifest = archiveManifest;
	}

}
