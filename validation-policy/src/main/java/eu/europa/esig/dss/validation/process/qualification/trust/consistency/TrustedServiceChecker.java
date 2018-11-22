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

import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public final class TrustedServiceChecker {

	private TrustedServiceChecker() {
	}

	public static boolean isFullyConsistent(TrustedServiceWrapper service) {
		return isLegalPersonConsistent(service) && isQCStatementConsistent(service) && isQSCDConsistent(service)
				&& isQSCDStatusAsInCertConsistent(service) && isUsageConsistent(service)
				&& isPreEIDASConsistent(service) && isQualifierAndAdditionalServiceInfoConsistent(service);
	}

	public static boolean isLegalPersonConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceLegalPersonConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQCStatementConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQCStatementConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQSCDConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQSCDConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQSCDStatusAsInCertConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQSCDStatusAsInCertConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isUsageConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceUsageConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isPreEIDASConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServicePreEIDASConsistency();
		return condition.isConsistent(service);
	}

	public static boolean isQualifierAndAdditionalServiceInfoConsistent(TrustedServiceWrapper service) {
		TrustedServiceCondition condition = new TrustedServiceQualifierAndAdditionalServiceInfoConsistency();
		return condition.isConsistent(service);
	}

}
