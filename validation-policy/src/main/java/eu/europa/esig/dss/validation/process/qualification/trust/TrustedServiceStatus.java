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
package eu.europa.esig.dss.validation.process.qualification.trust;

/**
 * ETSI TS 119 612 V2.2.1
 *
 */
public final class TrustedServiceStatus {

	/**
	 * Empty constructor
	 */
	private TrustedServiceStatus() {
	}

	/* Previous status */

	/** Before eIDAS 'undersupervision' status */
	public static final String UNDER_SUPERVISION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";

	/** Before eIDAS 'supervisionincessation' status */
	public static final String SUPERVISION_OF_SERVICE_IN_CESSATION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation";

	/** Before eIDAS 'supervisionceased' status */
	public static final String SUPERVISION_CEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased";

	/** Before eIDAS 'supervisionrevoked' status */
	public static final String SUPERVISION_REVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked";

	/** Before eIDAS 'accredited' status */
	public static final String ACCREDITED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";

	/** Before eIDAS 'accreditationceased' status */
	public static final String ACCREDITATION_CEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased";

	/** Before eIDAS 'accreditationrevoked' status */
	public static final String ACCREDITATION_REVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked";

	/* New status : eIDAS */

	/** After eIDAS 'granted' status */
	public static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

	/** After eIDAS 'withdrawn' status */
	public static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";

	/** After eIDAS 'setbynationallaw' status */
	public static final String SET_BY_NATIONAL_LAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw";

	/** After eIDAS 'recognisedatnationallevel' status */
	public static final String RECONIZED_AT_NATIONAL_LEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";

	/** After eIDAS 'deprecatedbynationallaw' status */
	public static final String DEPRECATED_BY_NATIONAL_LAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw";

	/** After eIDAS 'deprecatedatnationallevel' status */
	public static final String DEPRECATED_AT_NATIONAL_LEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel";

	/**
	 * Gets whether the given {@code status} is acceptable before eIDAS
	 *
	 * @param status {@link String} identifier
	 * @return TRUE if the status is acceptable before eIDAS, FALSE otherwise
	 */
	public static boolean isAcceptableStatusBeforeEIDAS(String status) {
		return UNDER_SUPERVISION.equals(status) || SUPERVISION_OF_SERVICE_IN_CESSATION.equals(status) || ACCREDITED.equals(status);
	}

	/**
	 * Gets whether the given {@code status} is acceptable after eIDAS
	 *
	 * @param status {@link String} identifier
	 * @return TRUE if the status is acceptable after eIDAS, FALSE otherwise
	 */
	public static boolean isAcceptableStatusAfterEIDAS(String status) {
		return GRANTED.equals(status);
	}

}
