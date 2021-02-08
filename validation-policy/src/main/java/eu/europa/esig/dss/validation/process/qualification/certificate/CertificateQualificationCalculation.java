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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.QSCDStatus;
import eu.europa.esig.dss.enumerations.CertificateQualifiedStatus;
import eu.europa.esig.dss.enumerations.CertificateType;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;

public class CertificateQualificationCalculation {

	private final CertificateWrapper endEntityCert;
	private final TrustedServiceWrapper caqcTrustService;

	public CertificateQualificationCalculation(CertificateWrapper endEntityCert, TrustedServiceWrapper caqcTrustService) {
		this.endEntityCert = endEntityCert;
		this.caqcTrustService = caqcTrustService;
	}

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
