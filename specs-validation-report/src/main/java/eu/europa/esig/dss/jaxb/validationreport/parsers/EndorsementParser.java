package eu.europa.esig.dss.jaxb.validationreport.parsers;

import eu.europa.esig.dss.jaxb.validationreport.enums.EndorsementType;

public class EndorsementParser {

	public static EndorsementType parse(String v) {
		return EndorsementType.fromString(v);
	}

	public static String print(EndorsementType v) {
		if (v == null) {
			return null;
		}
		return v.getValue();
	}

}
