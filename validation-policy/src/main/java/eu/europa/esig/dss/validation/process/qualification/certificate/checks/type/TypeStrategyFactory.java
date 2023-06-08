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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;

/**
 * Creates a {@code TypeStrategy}
 *
 */
public final class TypeStrategyFactory {

	/**
	 * Default constructor
	 */
	private TypeStrategyFactory() {
	}

	/**
	 * Creates a {@code TypeStrategy} from the certificate
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @return {@link TypeStrategy}
	 */
	public static TypeStrategy createTypeFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new TypeByCertificatePostEIDAS(signingCertificate);
		} else {
			return new TypeByCertificatePreEIDAS(signingCertificate);
		}
	}

	/**
	 * Creates a {@code TypeStrategy} from a Trusted Service
	 *
	 * @param trustService {@link TrustServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus}
	 * @param typeInCert {@link TypeStrategy}
	 * @return {@link TypeStrategy}
	 */
	public static TypeStrategy createTypeFromTL(TrustServiceWrapper trustService,
												CertificateQualifiedStatus qualified, TypeStrategy typeInCert) {
		return new TypeByTL(trustService, qualified, typeInCert);
	}

	/**
	 * Creates a {@code TypeStrategy} from a certificate and Trusted Service
	 *
	 * @param signingCertificate {@link CertificateWrapper}
	 * @param caQcTrustService {@link TrustServiceWrapper}
	 * @param qualified {@link CertificateQualifiedStatus}
	 * @return {@link TypeStrategy}
	 */
	public static TypeStrategy createTypeFromCertAndTL(CertificateWrapper signingCertificate, TrustServiceWrapper caQcTrustService,
			CertificateQualifiedStatus qualified) {
		TypeStrategy typeFromCert = createTypeFromCert(signingCertificate);
		return createTypeFromTL(caQcTrustService, qualified, typeFromCert);
	}

}
