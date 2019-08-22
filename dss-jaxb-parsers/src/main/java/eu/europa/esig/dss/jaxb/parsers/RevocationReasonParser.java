package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.RevocationReason;

public class RevocationReasonParser {

	private RevocationReasonParser() {
	}

	public static RevocationReason parseShortName(String v) {
		for (RevocationReason reason : RevocationReason.values()) {
			if (reason.getShortName().equals(v)) {
				return reason;
			}
		}
		return null;
	}

	public static String printShortName(RevocationReason v) {
		if (v != null) {
			return v.getShortName();
		} else {
			return null;
		}
	}

}
