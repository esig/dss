package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

/**
 * ETSI TS 119 612 V2.2.1
 */
public final class TrustedServiceStatus {

	private TrustedServiceStatus() {
	}

	/* Previous status */

	public static final String UNDER_SUPERVISION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";

	public static final String SUPERVISION_OF_SERVICE_IN_CESSATION = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation";

	public static final String SUPERVISION_CEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased";

	public static final String SUPERVISION_REVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked";

	public static final String ACCREDITED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";

	public static final String ACCREDITATION_CEASED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased";

	public static final String ACCREDITATION_REVOKED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked";

	/* New status : eIDAS */

	public static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

	public static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";

	public static final String SET_BY_NATIONAL_LAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw";

	public static final String RECONIZED_AT_NATIONAL_LEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";

	public static final String DEPRECATED_BY_NATIONAL_LAW = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw";

	public static final String DEPRECATED_AT_NATIONAL_LEVEL = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel";

	public static boolean isAcceptableStatusBeforeEIDAS(String status) {
		return UNDER_SUPERVISION.equals(status) || SUPERVISION_OF_SERVICE_IN_CESSATION.equals(status) || ACCREDITED.equals(status);
	}

	public static boolean isAcceptableStatusAfterEIDAS(String status) {
		return GRANTED.equals(status);
	}

}
