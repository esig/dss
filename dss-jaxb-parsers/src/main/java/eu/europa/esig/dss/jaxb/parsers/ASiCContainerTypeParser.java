package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.ASiCContainerType;

public class ASiCContainerTypeParser {

	private ASiCContainerTypeParser() {
	}

	public static ASiCContainerType parse(String v) {
		if (v != null) {
			return ASiCContainerType.valueByName(v);
		}
		return null;
	}

	public static String print(ASiCContainerType v) {
		if (v != null) {
			return v.toString();
		}
		return null;
	}

}
