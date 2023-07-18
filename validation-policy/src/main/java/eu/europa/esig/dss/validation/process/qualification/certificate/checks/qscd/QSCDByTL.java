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

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;

import java.util.List;

/**
 * Extracts QCSD status from a Trusted Service
 *
 */
class QSCDByTL implements QSCDStrategy {

	/** Trusted Service to extract QSCD status from */
	private final TrustServiceWrapper trustService;

	/** Qualification status of the certificate */
	private final CertificateQualifiedStatus qualified;

	/** QSCD strategy to be used */
	private final QSCDStrategy qscdFromCertificate;

	/**
	 * Default constructor
	 *
	 * @param trustService {@link TrustServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus}
	 * @param qscdFromCertificate {@link QSCDStrategy}
	 */
	public QSCDByTL(TrustServiceWrapper trustService, CertificateQualifiedStatus qualified,
					QSCDStrategy qscdFromCertificate) {
		this.trustService = trustService;
		this.qualified = qualified;
		this.qscdFromCertificate = qscdFromCertificate;
	}

	@Override
	public QSCDStatus getQSCDStatus() {
		if (trustService == null || !CertificateQualifiedStatus.isQC(qualified)) {
			return QSCDStatus.NOT_QSCD;

		} else {

			List<String> capturedQualifiers = trustService.getCapturedQualifierUris();

			// If overrules
			if (Utils.isCollectionNotEmpty(capturedQualifiers)) {

				if (EIDASUtils.isPostEIDAS(trustService.getStartDate())) {

					if (ServiceQualification.isQcWithQSCD(capturedQualifiers) || ServiceQualification.isQcQSCDManagedOnBehalf(capturedQualifiers)) {
						return QSCDStatus.QSCD;

					} else if (ServiceQualification.isQcQSCDStatusAsInCert(capturedQualifiers)) {
						return qscdFromCertificate.getQSCDStatus();

					} else if (ServiceQualification.isQcNoQSCD(capturedQualifiers)) {
						return QSCDStatus.NOT_QSCD;
					}

				} else { // pre eIDAS

					if (ServiceQualification.isQcWithSSCD(capturedQualifiers)) {
						return QSCDStatus.QSCD;

					} else if (ServiceQualification.isQcSSCDStatusAsInCert(capturedQualifiers)) {
						return qscdFromCertificate.getQSCDStatus();

					} else if (ServiceQualification.isQcNoSSCD(capturedQualifiers)) {
						return QSCDStatus.NOT_QSCD;
					}

				}

			}

			return qscdFromCertificate.getQSCDStatus();
		}
	}

}
