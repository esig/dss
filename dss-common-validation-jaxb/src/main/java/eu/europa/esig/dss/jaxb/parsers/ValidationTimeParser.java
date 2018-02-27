package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.ValidationTime;

public class ValidationTimeParser {

	public static ValidationTime parse(String v) {
		if (v != null) {
			return ValidationTime.valueOf(v);
		}
		return null;
	}

	public static String print(ValidationTime v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
