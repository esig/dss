package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.OrphanTokenType;

public class OrphanTokenTypeParser {

	private OrphanTokenTypeParser() {
	}

	public static OrphanTokenType parse(String v) {
		return OrphanTokenType.valueOf(v);
	}

	public static String print(OrphanTokenType v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
