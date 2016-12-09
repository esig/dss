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

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a DTO representation for a TSL service
 *
 */
public class TSLService {

	private String name;
	private String type;
	/* Spanish TSL contains certificate urls */
	private List<String> certificateUrls;
	private List<CertificateToken> certificates;
	private List<TSLServiceExtension> extensions;
	private List<TSLServiceStatus> status;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public List<String> getCertificateUrls() {
		return certificateUrls;
	}

	public void setCertificateUrls(List<String> certificateUrls) {
		this.certificateUrls = certificateUrls;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public void setCertificates(List<CertificateToken> certificates) {
		this.certificates = certificates;
	}

	public List<TSLServiceExtension> getExtensions() {
		return extensions;
	}

	public void setExtensions(List<TSLServiceExtension> extensions) {
		this.extensions = extensions;
	}

	public List<TSLServiceStatus> getStatus() {
		return status;
	}

	public void setStatus(List<TSLServiceStatus> status) {
		this.status = status;
	}

}
