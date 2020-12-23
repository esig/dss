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
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;

public final class TypeStrategyFactory {

	private TypeStrategyFactory() {
	}

	public static TypeStrategy createTypeFromCert(CertificateWrapper signingCertificate) {
		if (EIDASUtils.isPostEIDAS(signingCertificate.getNotBefore())) {
			return new TypeByCertificatePostEIDAS(signingCertificate);
		} else {
			return new TypeByCertificatePreEIDAS(signingCertificate);
		}
	}

	public static TypeStrategy createTypeFromTL(TrustedServiceWrapper trustedService, CertificateQualifiedStatus qualified, TypeStrategy typeInCert) {
		return new TypeByTL(trustedService, qualified, typeInCert);
	}

	public static TypeStrategy createTypeFromCertAndTL(CertificateWrapper signingCertificate, TrustedServiceWrapper caQcTrustedService,
			CertificateQualifiedStatus qualified) {
		TypeStrategy typeFromCert = createTypeFromCert(signingCertificate);
		return createTypeFromTL(caQcTrustedService, qualified, typeFromCert);
	}

}
