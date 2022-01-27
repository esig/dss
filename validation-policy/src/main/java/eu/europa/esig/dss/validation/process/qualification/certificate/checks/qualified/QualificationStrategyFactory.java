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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;

/**
 * Gets a {@code QualificationStrategy} to detect qualification strategy for a certificate
 *
 */
public final class QualificationStrategyFactory {

	/**
	 * Empty constructor
	 */
	private QualificationStrategyFactory() {
	}

	/**
	 * Creates {@code QualificationStrategy} from the certificate
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @return {@link QualificationStrategy}
	 */
	public static QualificationStrategy createQualificationFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new QualificationByCertificatePostEIDAS(signingCertificate);
		} else {
			return new QualificationByCertificatePreEIDAS(signingCertificate);
		}
	}

	/**
	 * Creates {@code QualificationStrategy} from the Trusted Service
	 *
	 * @param trustedService {@link TrustedServiceWrapper}
	 * @param qualifiedInCert {@link QualificationStrategy}
	 * @return {@link QualificationStrategy}
	 */
	public static QualificationStrategy createQualificationFromTL(TrustedServiceWrapper trustedService,
																  QualificationStrategy qualifiedInCert) {
		return new QualificationByTL(trustedService, qualifiedInCert);
	}

	/**
	 * Creates {@code QualificationStrategy} from the certificate and Trusted Service
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @param caQcTrustedService {@link TrustedServiceWrapper}
	 * @return {@link QualificationStrategy}
	 */
	public static QualificationStrategy createQualificationFromCertAndTL(CertificateWrapper signingCertificate,
																		 TrustedServiceWrapper caQcTrustedService) {
		QualificationStrategy qcFromCert = createQualificationFromCert(signingCertificate);
		return createQualificationFromTL(caQcTrustedService, qcFromCert);
	}

}
