package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.XmlRevocationOrigin;

public class RevocationOriginTypeParser {

	private RevocationOriginTypeParser() {
	}

	public static XmlRevocationOrigin parse(String v) {
		return XmlRevocationOrigin.valueOf(v);
	}

	public static String print(XmlRevocationOrigin v) {
		return v.name();
	}

}
