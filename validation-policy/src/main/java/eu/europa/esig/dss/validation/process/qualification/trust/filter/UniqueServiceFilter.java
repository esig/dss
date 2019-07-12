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

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationMatrix;
import eu.europa.esig.dss.validation.process.qualification.certificate.QSCDStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.QualifiedStatus;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qscd.QSCDStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.qualified.QualificationStrategyFactory;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategy;
import eu.europa.esig.dss.validation.process.qualification.certificate.checks.type.TypeStrategyFactory;

public class UniqueServiceFilter implements TrustedServiceFilter {

	private static final Logger LOG = LoggerFactory.getLogger(UniqueServiceFilter.class);

	private final CertificateWrapper endEntityCert;

	public UniqueServiceFilter(CertificateWrapper endEntityCert) {
		this.endEntityCert = endEntityCert;
	}

	@Override
	public List<TrustedServiceWrapper> filter(List<TrustedServiceWrapper> trustServices) {
		TrustedServiceWrapper selectedTrustedService = null;

		if (Utils.collectionSize(trustServices) == 1) {
			selectedTrustedService = trustServices.get(0);
		} else if (Utils.isCollectionNotEmpty(trustServices)) {
			LOG.info("More than one selected trust services");

			EnumMap<CertificateQualification, String> qualificationResults = new EnumMap<CertificateQualification, String>(
					CertificateQualification.class);
			for (TrustedServiceWrapper trustService : trustServices) {
				QualificationStrategy qcStrategy = QualificationStrategyFactory.createQualificationFromCertAndTL(endEntityCert, trustService);
				QualifiedStatus qualifiedStatus = qcStrategy.getQualifiedStatus();

				TypeStrategy typeStrategy = TypeStrategyFactory.createTypeFromCertAndTL(endEntityCert, trustService, qualifiedStatus);
				Type type = typeStrategy.getType();

				QSCDStrategy qscdStrategy = QSCDStrategyFactory.createQSCDFromCertAndTL(endEntityCert, trustService, qualifiedStatus);
				QSCDStatus qscdStatus = qscdStrategy.getQSCDStatus();

				CertificateQualification certQualification = CertQualificationMatrix.getCertQualification(qualifiedStatus, type, qscdStatus);

				if (!qualificationResults.containsKey(certQualification)) {
					qualificationResults.put(certQualification, trustService.getServiceName());
				}
			}

			if (qualificationResults.size() > 1) {
				LOG.warn("Unable to select the trust service ! Several possible conclusions {}", qualificationResults);
			} else {
				LOG.info("All trust services conclude with the same result");
				selectedTrustedService = trustServices.get(0);
			}
		}

		if (selectedTrustedService != null) {
			return Collections.singletonList(selectedTrustedService);
		} else {
			return Collections.emptyList();
		}
	}

}
