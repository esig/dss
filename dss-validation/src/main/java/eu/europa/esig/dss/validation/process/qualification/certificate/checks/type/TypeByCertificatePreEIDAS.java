/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.validation.process.CertificatePolicyIdentifiers;
import eu.europa.esig.dss.enumerations.CertificateType;

/**
 * Gets certificate usage type before eIDAS
 *
 */
class TypeByCertificatePreEIDAS implements TypeStrategy {

	/** Certificate to get usage type for */
	private final CertificateWrapper signingCertificate;

	/**
	 * Default constructor
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 */
	public TypeByCertificatePreEIDAS(CertificateWrapper signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	@Override
	public CertificateType getType() {
		if (signingCertificate.isQcCompliance() || CertificatePolicyIdentifiers.isQCP(signingCertificate)
				|| CertificatePolicyIdentifiers.isQCPPlus(signingCertificate)) {
			return CertificateType.ESIGN; // if QC -> ESign
		} else {
			return CertificateType.UNKNOWN;
		}
	}

}
