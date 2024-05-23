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
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.timedependent.TimeDependentValues;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.util.List;

/**
 * This class is a DTO representation for a TSL service
 */
public class TrustService implements Serializable {

	private static final long serialVersionUID = -7162121430380199621L;

	/** List of certificates */
	private final List<CertificateToken> certificates;

	/** Statuses based on time */
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> status;

	/**
	 * Default constructor
	 *
	 * @param certificates a list of {@link CertificateToken}s
	 * @param status {@link TimeDependentValues}
	 */
	public TrustService(final List<CertificateToken> certificates,
						final TimeDependentValues<TrustServiceStatusAndInformationExtensions> status) {
		this.certificates = certificates;
		this.status = status;
	}

	/**
	 * Gets a list of certificates
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getCertificates() {
		return certificates;
	}

	/**
	 * Gets status based on time
	 *
	 * @return {@link TimeDependentValues}
	 */
	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getStatusAndInformationExtensions() {
		return status;
	}

	/**
	 * Builds {@code TrustService}
	 */
	public static final class TrustServiceBuilder {

		/** List of certificates */
		private List<CertificateToken> certificates;

		/** Statuses based on time */
		private TimeDependentValues<TrustServiceStatusAndInformationExtensions> status;

		/**
		 * Default constructor
		 */
		public TrustServiceBuilder() {
			// empty
		}

		/**
		 * Sets a list of certificates
		 *
		 * @param certificates a list of {@link CertificateToken}s
		 * @return this {@link TrustServiceBuilder}
		 */
		public TrustServiceBuilder setCertificates(List<CertificateToken> certificates) {
			this.certificates = certificates;
			return this;
		}

		/**
		 * Sets a status
		 *
		 * @param status {@link TimeDependentValues}
		 * @return this {@link TrustServiceBuilder}
		 */
		public TrustServiceBuilder setStatusAndInformationExtensions(
				TimeDependentValues<TrustServiceStatusAndInformationExtensions> status) {
			this.status = status;
			return this;
		}

		/**
		 * Builds {@code TrustService}
		 *
		 * @return {@link TrustService}
		 */
		public TrustService build() {
			return new TrustService(certificates, status);
		}
		
	}

}
