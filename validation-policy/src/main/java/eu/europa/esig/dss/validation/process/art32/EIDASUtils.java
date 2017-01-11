package eu.europa.esig.dss.validation.process.art32;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

public final class EIDASUtils {

	/**
	 * Start date of the eIDAS regularisation
	 */
	private final static Date EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00.000Z").getTime();

	/**
	 * End of the grace period for eIDAS regularisation
	 */
	private final static Date EIDAS_GRACE_DATE = DatatypeConverter.parseDateTime("2017-07-01T00:00:00.000Z").getTime();

	public static boolean isPostEIDAS(Date date) {
		return (date != null && date.compareTo(EIDAS_DATE) >= 0);
	}

	public static boolean isPostGracePeriod(Date date) {
		return (date != null && date.compareTo(EIDAS_GRACE_DATE) >= 0);
	}

}
