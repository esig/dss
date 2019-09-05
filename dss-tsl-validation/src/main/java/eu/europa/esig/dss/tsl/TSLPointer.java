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
package eu.europa.esig.dss.tsl;

import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * This class is a DTO representation for a TSL pointer
 *
 */
public class TSLPointer {

	private String url;
	private String territory;
	private String mimeType;
	private List<CertificateToken> potentialSigners;

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getTerritory() {
		return territory;
	}

	public void setTerritory(String territory) {
		this.territory = territory;
	}

	public String getMimeType() {
		return mimeType;
	}

	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}

	public List<CertificateToken> getPotentialSigners() {
		return potentialSigners;
	}

	public void setPotentialSigners(List<CertificateToken> potentialSigners) {
		this.potentialSigners = potentialSigners;
	}

	@Override
	public String toString() {
		return "TSLPointer [url=" + url + ", territory=" + territory + ", mimeType=" + mimeType + ", potentialSigners=" + potentialSigners + "]";
	}

}
