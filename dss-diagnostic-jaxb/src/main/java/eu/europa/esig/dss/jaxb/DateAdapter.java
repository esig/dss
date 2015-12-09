package eu.europa.esig.dss.jaxb;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DateAdapter {

	private static final Logger logger = LoggerFactory.getLogger(DateAdapter.class);

	private static final String DATE_FORMAT = "dd/MM/yyyy HH:mm:ss.SSS";

	public static Date parse(String v) {
		try {
			SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
			sdf.setLenient(false);
			return sdf.parse(v);
		} catch (Exception e) {
			logger.warn("Unable to parse '" + v + "'");
		}
		return null;
	}

	public static String print(Date v) {
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
		return sdf.format(v);
	}

}
