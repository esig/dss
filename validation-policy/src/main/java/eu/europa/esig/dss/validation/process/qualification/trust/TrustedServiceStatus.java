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
public enum TrustedServiceStatus {

	/* Previous status */

	/** Before eIDAS 'undersupervision' status */
	UNDER_SUPERVISION("under supervision", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", false, true),

	/** Before eIDAS 'supervisionincessation' status */
	SUPERVISION_OF_SERVICE_IN_CESSATION("supervision in cessation", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation", false, true),

	/** Before eIDAS 'supervisionceased' status */
	SUPERVISION_CEASED("supervision ceased", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased", false, false),

	/** Before eIDAS 'supervisionrevoked' status */
	SUPERVISION_REVOKED("supervision revoked", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked", false, false),

	/** Before eIDAS 'accredited' status */
	ACCREDITED("accredited", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited", false, true),

	/** Before eIDAS 'accreditationceased' status */
	ACCREDITATION_CEASED("accreditation ceased", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased", false, false),

	/** Before eIDAS 'accreditationrevoked' status */
	ACCREDITATION_REVOKED("accreditation revoked", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked", false, false),

	/* New status : eIDAS */

	/** After eIDAS 'granted' status */
	GRANTED("granted", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", true, true),

	/** After eIDAS 'withdrawn' status */
	WITHDRAWN("withdrawn", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn", true, false),

	/** After eIDAS 'setbynationallaw' status */
	SET_BY_NATIONAL_LAW("set by national law", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw", true, false),

	/** After eIDAS 'recognisedatnationallevel' status */
	RECONIZED_AT_NATIONAL_LEVEL("recognised at national level", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel", true, false),

	/** After eIDAS 'deprecatedbynationallaw' status */
	DEPRECATED_BY_NATIONAL_LAW("deprecated by national law", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw", true, false),

	/** After eIDAS 'deprecatedatnationallevel' status */
	DEPRECATED_AT_NATIONAL_LEVEL("deprecated at national level", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel", true, false),
	;

	/** Identifier label */
	private final String shortName;

	/** Identifier URI */
	private final String uri;

	/** Whether the status is applicable after eIDAS (otherwise before) */
	private final boolean postEidas;

	/** Whether the status is valid (before or after eIDAS) */
	private final boolean valid;

	/**
	 * Empty constructor
	 */
	TrustedServiceStatus(String shortName, String uri, boolean postEidas, boolean valid) {
		this.shortName = shortName;
		this.uri = uri;
		this.postEidas = postEidas;
		this.valid = valid;
	}

	/**
	 * Gets the user-friendly label
	 *
	 * @return {@link String}
	 */
	public String getShortName() {
		return shortName;
	}

	/**
	 * Gets the URI
	 *
	 * @return {@link String}
	 */
	public String getUri() {
		return uri;
	}

	/**
	 * Whether the status is related to pre-eIDAS.
	 *
	 * @return TRUE if the status is related to pre-eIDAS, FALSE otherwise
	 */
	public boolean isPreEidas() {
		return !isPostEidas();
	}

	/**
	 * Whether the status is related to post-eIDAS.
	 *
	 * @return TRUE if the status is related to post-eIDAS, FALSE otherwise
	 */
	public boolean isPostEidas() {
		return postEidas;
	}

	/**
	 * Whether the status identifies a valid trust service
	 *
	 * @return whether the status identifies a valid trust service
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * Gets whether the given {@code status} is acceptable before eIDAS
	 *
	 * @param uri {@link String} identifying the trust service status
	 * @return TRUE if the status is acceptable before eIDAS, FALSE otherwise
	 */
	public static boolean isAcceptableStatusBeforeEIDAS(String uri) {
		TrustedServiceStatus tss = fromUri(uri);
		return tss != null && tss.isPreEidas() && tss.isValid();
	}

	/**
	 * Gets whether the given {@code status} is acceptable after eIDAS
	 *
	 * @param uri {@link String} identifying the trust service status
	 * @return TRUE if the status is acceptable after eIDAS, FALSE otherwise
	 */
	public static boolean isAcceptableStatusAfterEIDAS(String uri) {
		TrustedServiceStatus tss = fromUri(uri);
		return tss != null && tss.isPostEidas() && tss.isValid();
	}

	/**
	 * This method returns a corresponding {@code TrustedServiceStatus} by the given {@code uri}
	 *
	 * @param uri {@link String} to get {@code TrustedServiceStatus} for
	 * @return {@link TrustedServiceStatus}
	 */
	public static TrustedServiceStatus fromUri(String uri) {
		for (TrustedServiceStatus status : values()) {
			if (status.getUri().equals(uri)) {
				return status;
			}
		}
		return null;
	}

}
