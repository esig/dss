package eu.europa.esig.dss.validation.process.art32;

import java.util.Date;

import javax.xml.bind.DatatypeConverter;

public final class EIDASConstants {

	/**
	 * Start date of the eIDAS regularisation
	 */
	public final static Date EIDAS_DATE = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();

	/**
	 * End of the grace periode for eIDAS regularisation
	 */
	public final static Date EIDAS_GRACE_DATE = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

}
