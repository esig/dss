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

import eu.europa.esig.dss.util.TimeDependentValues;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This class is a DTO representation for a TSL service
 */
public class TSLService {

	private String name;
	private List<CertificateToken> certificates;
	private TimeDependentValues<TSLServiceStatusAndInformationExtensions> status;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public void setCertificates(List<CertificateToken> certificates) {
		this.certificates = certificates;
	}

	public TimeDependentValues<TSLServiceStatusAndInformationExtensions> getStatusAndInformationExtensions() {
		return status;
	}

	public void setStatusAndInformationExtensions(TimeDependentValues<TSLServiceStatusAndInformationExtensions> status) {
		this.status = status;
	}

}
