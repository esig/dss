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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.GrantedServiceFilter;

import java.util.List;

/**
 * Gets certificate qualification status base on information extracted from a TrustedService
 *
 */
class QualificationByTL implements QualificationStrategy {

	/** Trusted Service to get qualification status from */
	private final TrustedServiceWrapper trustedService;

	/** Qualification strategy to be used */
	private final QualificationStrategy qualifiedInCert;

	/**
	 * Default constructor
	 *
	 * @param trustedService {@link TrustedServiceWrapper}
	 * @param qualifiedInCert {@link QualificationStrategy}
	 */
	public QualificationByTL(TrustedServiceWrapper trustedService, QualificationStrategy qualifiedInCert) {
		this.trustedService = trustedService;
		this.qualifiedInCert = qualifiedInCert;
	}

	@Override
	public CertificateQualifiedStatus getQualifiedStatus() {
		if (trustedService == null) {
			return CertificateQualifiedStatus.NOT_QC;
		} else {

			GrantedServiceFilter grantedFilter = new GrantedServiceFilter();
			if (!grantedFilter.isAcceptable(trustedService)) {
				return CertificateQualifiedStatus.NOT_QC;
			}

			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {
				if (ServiceQualification.isNotQualified(capturedQualifiers)) {
					return CertificateQualifiedStatus.NOT_QC;
				}

				if (ServiceQualification.isQcStatement(capturedQualifiers)) {
					return CertificateQualifiedStatus.QC;
				}
			}

			return qualifiedInCert.getQualifiedStatus();
		}
	}

}
