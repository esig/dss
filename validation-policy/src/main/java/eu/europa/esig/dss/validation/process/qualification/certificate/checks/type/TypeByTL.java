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

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

class TypeByTL implements TypeStrategy {

	private final TrustedServiceWrapper trustedService;
	private final QualifiedStatus qualified;
	private final TypeStrategy typeInCert;

	public TypeByTL(TrustedServiceWrapper trustedService, QualifiedStatus qualified, TypeStrategy typeInCert) {
		this.trustedService = trustedService;
		this.qualified = qualified;
		this.typeInCert = typeInCert;
	}

	@Override
	public Type getType() {

		// overrules are only applicable when the certificate is qualified (cert + TL)
		if (QualifiedStatus.isQC(qualified)) {

			if (EIDASUtils.isPreEIDAS(trustedService.getStartDate())) {
				return Type.ESIGN;
			}

			List<String> usageQualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

			// If overrules
			if (Utils.isCollectionNotEmpty(usageQualifiers)) {

				if (ServiceQualification.isQcForEsig(usageQualifiers)) {
					return Type.ESIGN;
				}

				if (ServiceQualification.isQcForEseal(usageQualifiers)) {
					return Type.ESEAL;
				}

				if (ServiceQualification.isQcForWSA(usageQualifiers)) {
					return Type.WSA;
				}

			}
		}

		return typeInCert.getType();
	}

}
