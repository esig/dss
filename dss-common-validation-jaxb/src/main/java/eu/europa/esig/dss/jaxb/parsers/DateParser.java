package eu.europa.esig.dss.jaxb.parsers;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DateParser {

	private static final Logger logger = LoggerFactory.getLogger(DateParser.class);

	private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

	private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

	public static Date parse(String v) {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			sdf.setLenient(false);
			return sdf.parse(v);
		} catch (Exception e) {
			logger.warn("Unable to parse '" + v + "'");
		}
		return null;
	}

	public static String print(Date v) {
		if (v != null) {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setTimeZone(UTC);
			return sdf.format(v);
		}
		return null;
	}

}
