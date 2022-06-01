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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;

import java.util.List;

/**
 * Gets certificate usage type based on the information extracted from a TrustedService
 *
 */
class TypeByTL implements TypeStrategy {

	/** Trusted Service to get certificate usage type from */
	private final TrustedServiceWrapper trustedService;

	/** Certificate qualified status */
	private final CertificateQualifiedStatus qualified;

	/** Certificate's usage type extraction strategy */
	private final TypeStrategy typeInCert;

	/**
	 * Default constructor
	 *
	 * @param trustedService {@link TrustedServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus}
	 * @param typeInCert {@link TypeStrategy}
	 */
	public TypeByTL(TrustedServiceWrapper trustedService, CertificateQualifiedStatus qualified,
					TypeStrategy typeInCert) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.typeInCert = typeInCert;
	}

	@Override
	public CertificateType getType() {

		// overrules are only applicable when the certificate is qualified (cert + TL)
		if (CertificateQualifiedStatus.isQC(qualified)) {

			if (trustedService == null) {
				return CertificateType.UNKNOWN;
			}

			if (EIDASUtils.isPreEIDAS(trustedService.getStartDate())) {
				return CertificateType.ESIGN;
			}

			List<String> usageQualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

			if (Utils.collectionSize(usageQualifiers) > 1) {
				return CertificateType.UNKNOWN;

			} else if (Utils.isCollectionNotEmpty(usageQualifiers)) {
				// If overrules

				if (ServiceQualification.isQcForEsig(usageQualifiers)) {
					return CertificateType.ESIGN;
				}

				if (ServiceQualification.isQcForEseal(usageQualifiers)) {
					return CertificateType.ESEAL;
				}

				if (ServiceQualification.isQcForWSA(usageQualifiers)) {
					return CertificateType.WSA;
				}

			}

		}

		return typeInCert.getType();
	}

}
