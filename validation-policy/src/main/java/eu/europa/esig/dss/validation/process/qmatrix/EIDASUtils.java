package eu.europa.esig.dss.validation.process.qmatrix;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

public final class EIDASUtils {

	private EIDASUtils() {
	}

	/**
	 * Start date of the eIDAS regulation
	 * 
	 * Regulation was signed in Brussels : 1st of July 00:00 Brussels = 30th of June 22:00 UTC
	 */
	private final static Date EIDAS_DATE = DatatypeConverter.parseDateTime("2016-06-30T22:00:00.000Z").getTime();

	/**
	 * End of the grace period for eIDAS regulation
	 */
	private final static Date EIDAS_GRACE_DATE = DatatypeConverter.parseDateTime("2017-06-30T22:00:00.000Z").getTime();

	public static boolean isPostEIDAS(Date date) {
		return date != null && date.compareTo(EIDAS_DATE) >= 0;
	}

	public static boolean isPreEIDAS(Date date) {
		return date != null && date.compareTo(EIDAS_DATE) < 0;
	}

	public static boolean isPostGracePeriod(Date date) {
		return date != null && date.compareTo(EIDAS_GRACE_DATE) >= 0;
	}

}
