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

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class QualificationByTL implements QualificationStrategy {

	private final TrustedServiceWrapper trustedService;
	private final QualificationStrategy qualifiedInCert;

	public QualificationByTL(TrustedServiceWrapper trustedService, QualificationStrategy qualifiedInCert) {
		this.trustedService = trustedService;
		this.qualifiedInCert = qualifiedInCert;
	}

	@Override
	public QualifiedStatus getQualifiedStatus() {
		if (trustedService == null) {
			return QualifiedStatus.NOT_QC;
		} else {
			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {
				if (ServiceQualification.isNotQualified(capturedQualifiers)) {
					return QualifiedStatus.NOT_QC;
				}

				if (ServiceQualification.isQcStatement(capturedQualifiers)) {
					return QualifiedStatus.QC;
				}
			}

			return qualifiedInCert.getQualifiedStatus();
		}
	}

}
