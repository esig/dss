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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.EIDASUtils;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;

import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

/**
 * Allowed services are :
 * <ul>
 * <li>cert type T1 = ASi T1</li>
 * <li>cert type T1 = ASi T2 + QCForXXX T2 (overrule)</li>
 * </ul>
 */
public class ServiceByCertificateTypeFilter extends AbstractTrustedServiceFilter {

	/** Certificate to be checked */
	private final CertificateWrapper certificate;

	/**
	 * Default constructor
	 *
	 * @param certificate {@link CertificateWrapper} to get trusted services for
	 */
	public ServiceByCertificateTypeFilter(CertificateWrapper certificate) {
		this.certificate = certificate;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		Date issuance = certificate.getNotBefore();

		if (EIDASUtils.isPostEIDAS(issuance)) {

			final List<String> additionalServiceInfos = service.getAdditionalServiceInfos();
			boolean asiEsign = AdditionalServiceInformation.isForeSignatures(additionalServiceInfos);
			boolean asiEseals = AdditionalServiceInformation.isForeSeals(additionalServiceInfos);
			boolean asiWsa = AdditionalServiceInformation.isForWebAuth(additionalServiceInfos);

			final List<String> capturedQualifiers = service.getCapturedQualifiers();
			boolean qcForEsign = ServiceQualification.isQcForEsig(capturedQualifiers);
			boolean qcForEseals = ServiceQualification.isQcForEseal(capturedQualifiers);
			boolean qcForWSA = ServiceQualification.isQcForWSA(capturedQualifiers);

			// if QcStatement and no types -> for eSig by default (see TS 119 615, Table 1)
			qcForEsign = qcForEsign || (!qcForEseals && !qcForWSA && certificate.isQcCompliance());

			boolean onlyOneQcForXXX = Stream.of(qcForEsign, qcForEseals, qcForWSA).filter(b -> b).count() == 1;

			TypeStrategy strategy = TypeStrategyFactory.createTypeFromCert(certificate);
			CertificateType certType = strategy.getType();

			boolean overruleForEsign = asiEsign && qcForEsign && onlyOneQcForXXX;
			boolean overruleForEseals = asiEseals && qcForEseals && onlyOneQcForXXX;
			boolean overruleForWSA = asiWsa && qcForWSA && onlyOneQcForXXX;

			switch (certType) {
				case ESIGN:
					return asiEsign || overruleForEseals || overruleForWSA;
				case ESEAL:
					return asiEseals || overruleForEsign || overruleForWSA;
				case WSA:
					return asiWsa || overruleForEseals || overruleForEsign;
				case UNKNOWN:
					// continue to identify qualification (keeping unknown type)
					return true;
				default:
					throw new UnsupportedOperationException(String.format("Unsupported CertificateType : %s", certType));
			}

		}

		return true;
	}

}
