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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;

import java.util.List;
import java.util.stream.Stream;

/**
 * A Trusted Service can only have one of these values {QcForEsig, QcForEseal or QcForWSA} or none.
 * 
 */
class TrustServiceUsageConsistency implements TrustServiceCondition {

	/**
	 * Default constructor
	 */
	public TrustServiceUsageConsistency() {
		// empty
	}

	@Override
	public boolean isConsistent(TrustServiceWrapper trustService) {

		List<String> capturedQualifiers = trustService.getCapturedQualifierUris();

		boolean qcForEsig = ServiceQualification.isQcForEsig(capturedQualifiers);
		boolean qcForEseal = ServiceQualification.isQcForEseal(capturedQualifiers);
		boolean qcForWSA = ServiceQualification.isQcForWSA(capturedQualifiers);

		boolean noneOfThem = !(qcForEsig || qcForEseal || qcForWSA);
		boolean onlyOneOfThem = Stream.of(qcForEsig, qcForEseal, qcForWSA).filter(b -> b).count() == 1;

		return noneOfThem || onlyOneOfThem;
	}

}
