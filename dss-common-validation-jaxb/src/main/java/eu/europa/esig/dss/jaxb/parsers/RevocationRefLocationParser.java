package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlRevocationRefLocation;

public class RevocationRefLocationParser {

	private RevocationRefLocationParser() {
	}

	public static XmlRevocationRefLocation parse(String v) {
		return XmlRevocationRefLocation.valueOf(v);
	}

	public static String print(XmlRevocationRefLocation v) {
		return v.name();
	}

}
