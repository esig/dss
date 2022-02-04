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

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.AdditionalServiceInformation;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

class TrustedServiceQualifierAndAdditionalServiceInfoConsistency implements TrustedServiceCondition {

	private static final Map<String, String> CORRESPONDANCE_MAP_QUALIFIER_ASI;

	static {
		CORRESPONDANCE_MAP_QUALIFIER_ASI = new HashMap<>();

		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESIG, AdditionalServiceInformation.FOR_ESIGNATURES);
		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_ESEAL, AdditionalServiceInformation.FOR_ESEALS);
		CORRESPONDANCE_MAP_QUALIFIER_ASI.put(ServiceQualification.QC_FOR_WSA, AdditionalServiceInformation.FOR_WEB_AUTHENTICATION);
	}

	@Override
	public boolean isConsistent(TrustedServiceWrapper trustedService) {

		List<String> asis = trustedService.getAdditionalServiceInfos();
		List<String> qualifiers = ServiceQualification.getUsageQualifiers(trustedService.getCapturedQualifiers());

		return isQualifierInAdditionServiceInfos(qualifiers, asis);
	}

	private boolean isQualifierInAdditionServiceInfos(List<String> qualifiers, List<String> asis) {
		if (Utils.collectionSize(asis) >= 1) {
			// Cannot have more than 1 usage (>1 is covered in
			// TrustedServiceUsageConsistency)
			if (Utils.collectionSize(qualifiers) == 1) {
				String currentUsage = qualifiers.get(0);
				String expectedASI = CORRESPONDANCE_MAP_QUALIFIER_ASI.get(currentUsage);
				return asis.contains(expectedASI);
			}
		}
		return true;
	}

}
