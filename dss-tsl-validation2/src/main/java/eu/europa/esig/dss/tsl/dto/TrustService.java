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
package eu.europa.esig.dss.tsl.dto;

import java.io.Serializable;
import java.util.List;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.util.TimeDependentValues;

/**
 * This class is a DTO representation for a TSL service
 */
public class TrustService implements Serializable {

	private static final long serialVersionUID = -7162121430380199621L;
	
	private final List<CertificateToken> certificates;
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> status;
	
	public TrustService(final List<CertificateToken> certificates, final TimeDependentValues<TrustServiceStatusAndInformationExtensions> status) {
		this.certificates = certificates;
		this.status = status;
	}

	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getStatusAndInformationExtensions() {
		return status;
	}
	
	public static final class TrustServiceBuilder {

		private List<CertificateToken> certificates;
		private TimeDependentValues<TrustServiceStatusAndInformationExtensions> status;
		
		public TrustServiceBuilder() {
		}

		public TrustServiceBuilder setCertificates(List<CertificateToken> certificates) {
			this.certificates = certificates;
			return this;
		}

		public TrustServiceBuilder setStatusAndInformationExtensions(TimeDependentValues<TrustServiceStatusAndInformationExtensions> status) {
			this.status = status;
			return this;
		}
		
		public TrustService build() {
			return new TrustService(certificates, status);
		}
		
	}

}
