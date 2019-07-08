package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.RevocationReason;

public class RevocationReasonParser {

	private RevocationReasonParser() {
	}

	public static RevocationReason parse(String v) {
		return RevocationReason.valueOf(v);
	}

	public static String print(RevocationReason v) {
		if (v != null) {
			return v.name();
		} else {
			return null;
		}
	}

}
