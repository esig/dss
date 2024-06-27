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
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.EnumMap;
import java.util.List;

/**
 * This class is used to select a TrustService that is unambiguous and does not have conflicts with other TrustServices.
 * In case of a conflict for the given {@code endEntityCert}, none of the TrustServices is returned.
 *
 */
public class UniqueServiceFilter implements TrustServiceFilter {

	private static final Logger LOG = LoggerFactory.getLogger(UniqueServiceFilter.class);

	/** Certificate to check TrustServices for */
	private final CertificateWrapper endEntityCert;

	/**
	 * Default constructor
	 *
	 * @param endEntityCert {@link CertificateWrapper} to check TrustServices for
	 */
	public UniqueServiceFilter(CertificateWrapper endEntityCert) {
		this.endEntityCert = endEntityCert;
	}

	@Override
	public List<TrustServiceWrapper> filter(List<TrustServiceWrapper> trustServices) {
		TrustServiceWrapper selectedTrustService = null;

		if (Utils.collectionSize(trustServices) == 1) {
			selectedTrustService = trustServices.get(0);
		} else if (Utils.isCollectionNotEmpty(trustServices)) {
			LOG.info("More than one selected trust services");

			EnumMap<CertificateQualification, List<String>> qualificationResults = new EnumMap<>(
					CertificateQualification.class);
			for (TrustServiceWrapper trustService : trustServices) {
				CertificateQualificationCalculator calculator = new CertificateQualificationCalculator(endEntityCert, trustService);
				CertificateQualification certQualification = calculator.getQualification();
				qualificationResults.putIfAbsent(certQualification, trustService.getServiceNames()); // use putIfAbsent as trustService.getServiceNames() may return null
			}

			if (qualificationResults.size() > 1) {
				LOG.warn("Unable to select the trust service ! Several possible conclusions {}", qualificationResults);
			} else {
				LOG.info("All trust services conclude with the same result");
				selectedTrustService = trustServices.get(0);
			}
		}

		if (selectedTrustService != null) {
			return Collections.singletonList(selectedTrustService);
		} else {
			return Collections.emptyList();
		}
	}

}
