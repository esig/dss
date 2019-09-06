package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EndorsementType;

public class EndorsementTypeParser {

	private EndorsementTypeParser() {
	}

	public static EndorsementType parse(String v) {
		if (v != null) {
			return EndorsementType.fromString(v);
		}
		return null;
	}

	public static String print(EndorsementType v) {
		if (v != null) {
			return v.getValue();
		}
		return null;
	}

}
