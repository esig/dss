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

import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.MimeType;

public class ManifestEntry {
	
	private String filename;
	private MimeType mimeType;
	private Digest digest;
	
	// used for reference validation
	private boolean dataFound;
	private boolean dataIntact;
	
	public String getFileName() {
		return filename;
	}
	
	public void setFileName(String fileName) {
		this.filename = fileName;
	}
	
	public MimeType getMimeType() {
		return mimeType;
	}
	
	public void setMimeType(MimeType mimeType) {
		this.mimeType = mimeType;
	}
	
	public Digest getDigest() {
		return digest;
	}
	
	public void setDigest(Digest digest) {
		this.digest = digest;
	}
	
	public boolean isFound() {
		return dataFound;
	}
	
	public void setFound(boolean found) {
		this.dataFound = found;
	}
	
	public boolean isIntact() {
		return dataIntact;
	}
	
	public void setIntact(boolean intact) {
		this.dataIntact = intact;
	}

}
