package eu.europa.esig.dss.validation.policy;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import eu.europa.esig.dss.DSSException;

public final class DateUtils {

	public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";

	private DateUtils() {
	}

	/**
	 * Converts the given string representation of the date using the format pattern.
	 *
	 * @param format
	 *            the format to use
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date}
	 * @throws DSSException
	 *             if the conversion is not possible the {@code DSSException} is thrown.
	 */
	public static Date parseDate(final String format, final String dateString) {
		try {
			final SimpleDateFormat sdf = new SimpleDateFormat(format);
			sdf.setLenient(false);
			return sdf.parse(dateString);
		} catch (ParseException e) {
			throw new DSSException("Unable to parse date " + dateString + " (format:" + format + ")", e);
		}
	}

}
