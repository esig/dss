package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

public class ObjectIdentifierQualifierParser {

	private ObjectIdentifierQualifierParser() {
	}

	public static ObjectIdentifierQualifier parse(String v) {
		return ObjectIdentifierQualifier.fromValue(v);
	}

	public static String print(ObjectIdentifierQualifier v) {
		if (v != null) {
			return v.getValue();
		} else {
			return null;
		}
	}

}
