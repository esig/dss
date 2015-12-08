package eu.europa.esig.dss;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.lang.StringUtils;

public final class DateUtils {

	public static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd";
	public static final String DEFAULT_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

	private DateUtils() {
	}

	/**
	 * Converts the given string representation of the date using the {@code DEFAULT_DATE_TIME_FORMAT}.
	 *
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date}
	 * @throws DSSException
	 *             if the conversion is not possible the {@code DSSException} is thrown.
	 */
	public static Date parseDate(final String dateString) throws DSSException {
		try {
			final SimpleDateFormat sdf = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (ParseException e) {
			throw new DSSException(e);
		}
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
	public static Date parseDate(final String format, final String dateString) throws DSSException {
		try {
			final SimpleDateFormat sdf = new SimpleDateFormat(format);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (ParseException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Converts the given string representation of the date using the {@code DEFAULT_DATE_TIME_FORMAT}. If an exception is frown durring the prsing then null is returned.
	 *
	 * @param dateString
	 *            the date string representation
	 * @return the {@code Date} or null if the parsing is not possible
	 */
	public static Date quietlyParseDate(final String dateString) {
		try {
			final SimpleDateFormat sdf = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT);
			final Date date = sdf.parse(dateString);
			return date;
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Formats the given date-time using the default pattern: {@code DSSUtils.DEFAULT_DATE_TIME_FORMAT}
	 *
	 * @param date
	 * @return
	 */
	public static String formatDate(final Date date) {
		if (date != null) {
			final String stringDate = new SimpleDateFormat(DEFAULT_DATE_TIME_FORMAT).format(date);
			return stringDate;
		}
		return StringUtils.EMPTY;
	}

	/**
	 * This method returns an UTC date base on the year, the month and the day. The year must be encoded as 1978... and not 78
	 *
	 * @param year
	 *            the value used to set the YEAR calendar field.
	 * @param month
	 *            the month. Month value is 0-based. e.g., 0 for January.
	 * @param day
	 *            the value used to set the DAY_OF_MONTH calendar field.
	 * @return the UTC date base on parameters
	 */
	public static Date getUtcDate(final int year, final int month, final int day) {
		final Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.set(year, month, day, 0, 0, 0);
		final Date date = calendar.getTime();
		return date;
	}

}
