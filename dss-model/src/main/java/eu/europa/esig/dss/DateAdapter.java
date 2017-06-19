package eu.europa.esig.dss;

import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * This class is an adapter for java.util.Date in SOAP WS
 */
public class DateAdapter extends XmlAdapter<String, Date> {

	private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

	@Override
	public Date unmarshal(String v) throws Exception {
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
		sdf.setLenient(false);
		return sdf.parse(v);
	}

	@Override
	public String marshal(Date v) throws Exception {
		SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
		return sdf.format(v);
	}

}
