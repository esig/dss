/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;

/**
 * This class is used to determine certificate's qualification based on its content and
 * the given {@code TrustServiceWrapper}
 *
 */
public class CertificateQualificationCalculator {

	/** Certificate to get qualification for */
	private final CertificateWrapper endEntityCert;

	/** Trusted Service to be used to help to determine the qualification */
	private final TrustServiceWrapper caqcTrustService;

	/**
	 * Default constructor
	 *
	 * @param endEntityCert {@link CertificateWrapper} to get qualification for
	 * @param caqcTrustService {@link TrustServiceWrapper} related TrustService to extract qualification from
	 */
	public CertificateQualificationCalculator(CertificateWrapper endEntityCert, TrustServiceWrapper caqcTrustService) {
		this.endEntityCert = endEntityCert;
		this.caqcTrustService = caqcTrustService;
	}

	/**
	 * This method returns the qualification result for the given {@code CertificateWrapper}
	 *
	 * @return {@link CertificateQualification}
	 */
	public CertificateQualification getQualification() {
		QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(endEntityCert, caqcTrustService);
		CertificateQualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();

		TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(endEntityCert, caqcTrustService, qualifiedStatus);
		CertificateType type = typeStrategy.getType();

		QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(endEntityCert, caqcTrustService, qualifiedStatus);
		QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();

		return CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);
	}

}
