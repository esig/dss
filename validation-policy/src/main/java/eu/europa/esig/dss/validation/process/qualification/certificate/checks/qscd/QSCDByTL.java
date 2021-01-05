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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;

import java.util.List;

class QSCDByTL implements QSCDStrategy {

	private final TrustedServiceWrapper trustedService;
	private final CertificateQualifiedStatus qualified;
	private final QSCDStrategy qscdFromCertificate;

	public QSCDByTL(TrustedServiceWrapper trustedService, CertificateQualifiedStatus qualified, QSCDStrategy qscdFromCertificate) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.qscdFromCertificate = qscdFromCertificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {
		if (trustedService == null || !CertificateQualifiedStatus.isQC(qualified)) {
			return QSCDStatus.NOT_QSCD;
		} else {

			List<String> capturedQualifiers = trustedService.getCapturedQualifiers();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				if (ServiceQualification.isQcNoQSCD(capturedQualifiers)) {
					return QSCDStatus.NOT_QSCD;
				}

				if (ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers)) {
					return QSCDStatus.QSCD;
				}

			}

			return qscdFromCertificate.getQSCDStatus();
		}
	}

}
