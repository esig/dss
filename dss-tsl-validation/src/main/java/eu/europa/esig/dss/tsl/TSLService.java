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

import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a DTO representation for a TSL service
 *
 */
public class TSLService {

	private String name;
	private String status;
	private String type;
	private Date startDate;
	private Date endDate;
	/* Spanish TSL contains certificate urls */
	private List<String> certificateUrls;
	private List<CertificateToken> certificates;
	private List<X500Principal> x500Principals;
	private List<TSLServiceExtension> extensions;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}

	public Date getEndDate() {
		return endDate;
	}

	public void setEndDate(Date endDate) {
		this.endDate = endDate;
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

	public List<X500Principal> getX500Principals() {
		return x500Principals;
	}

	public void setX500Principals(List<X500Principal> x500Principals) {
		this.x500Principals = x500Principals;
	}

	public List<TSLServiceExtension> getExtensions() {
		return extensions;
	}

	public void setExtensions(List<TSLServiceExtension> extensions) {
		this.extensions = extensions;
	}

}
