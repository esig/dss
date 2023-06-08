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

/**
 * Contain util method to check validity of the {@code TrustServiceWrapper}
 *
 */
public final class TrustServiceChecker {

	/**
	 * Default constructor
	 */
	private TrustServiceChecker() {
	}

	/**
	 * Checks whether the legal person identifiers within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isLegalPersonConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceLegalPersonConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the QC statement identifiers within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isQCStatementConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceQCStatementConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the QSCD identifiers within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isQSCDConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceQSCDConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the QSCD as in cert identifier within {@code TrustServiceWrapper} is consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isQSCDStatusAsInCertConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceQSCDStatusAsInCertConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the usage type identifiers within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isUsageConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceUsageConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the statuses before eIDAS within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isPreEIDASStatusConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceStatusPreEIDASConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the qualifiers and additional service information before eIDAS
	 * within {@code TrustServiceWrapper} are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isPreEIDASQualifierAndAdditionalServiceInfoConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceQualifierAndAdditionalServiceInfoPreEIDASConsistency();
		return condition.isConsistent(service);
	}

	/**
	 * Checks whether the qualifiers and additional service information are consistent
	 *
	 * @param service {@link TrustServiceWrapper}
	 * @return TRUE if the Trusted Service is consistent, FALSE otherwise
	 */
	public static boolean isQualifierAndAdditionalServiceInfoConsistent(TrustServiceWrapper service) {
		TrustServiceCondition condition = new TrustServiceQualifierAndAdditionalServiceInfoConsistency();
		return condition.isConsistent(service);
	}

}
