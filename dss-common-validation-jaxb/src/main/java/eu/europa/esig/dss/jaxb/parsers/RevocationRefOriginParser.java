package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlRevocationRefOrigin;

public class RevocationRefOriginParser {

	private RevocationRefOriginParser() {
	}

	public static XmlRevocationRefOrigin parse(String v) {
		return XmlRevocationRefOrigin.valueOf(v);
	}

	public static String print(XmlRevocationRefOrigin v) {
		return v.name();
	}

}
