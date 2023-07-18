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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.AdditionalServiceInformation;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import eu.europa.esig.dss.utils.Utils;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * This class verifies consistency of the qualifiers and AdditionalServiceInformation within a Trusted Service
 *
 */
class TrustServiceQualifierAndAdditionalServiceInfoConsistency implements TrustServiceCondition {

	/** The correspondence map */
	private static final Map<ServiceQualification, AdditionalServiceInformation> CORRESPONDENCE_MAP_QUALIFIER_ASI;

	static {
		CORRESPONDENCE_MAP_QUALIFIER_ASI = new EnumMap<>(ServiceQualification.class);

		CORRESPONDENCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESIG, AdditionalServiceInformation.FOR_ESIGNATURES);
		CORRESPONDENCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESEAL, AdditionalServiceInformation.FOR_ESEALS);
		CORRESPONDENCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_WSA, AdditionalServiceInformation.FOR_WEB_AUTHENTICATION);
	}

	/**
	 * Default constructor
	 */
	public TrustServiceQualifierAndAdditionalServiceInfoConsistency() {
		// empty
	}

	@Override
	public boolean isConsistent(TrustServiceWrapper trustService) {
		List<String> asis = trustService.getAdditionalServiceInfos();
		List<String> qualifiers = ServiceQualification.getUsageQualifiers(trustService.getCapturedQualifierUris());
		return isQualifierInAdditionServiceInfos(qualifiers, asis);
	}

	private boolean isQualifierInAdditionServiceInfos(List<String> qualifiers, List<String> asis) {
		if (Utils.collectionSize(asis) >= 1) {
			// Cannot have more than 1 usage (>1 is covered in TrustServiceUsageConsistency)
			if (Utils.collectionSize(qualifiers) == 1) {
				String currentUsage = qualifiers.get(0);
				ServiceQualification serviceQualification = ServiceQualification.getByUri(currentUsage);
				AdditionalServiceInformation expectedASI = CORRESPONDENCE_MAP_QUALIFIER_ASI.get(serviceQualification);
				return expectedASI != null && asis.contains(expectedASI.getUri());
			}
		}
		return true;
	}

}
