package eu.europa.esig.jaxb.trustedlist.ecc.parsers;

import eu.europa.esig.jaxb.trustedlist.ecc.enums.KeyUsageBit;

public final class KeyUsageBitParser {

	private KeyUsageBitParser() {
	}

	public static KeyUsageBit parse(String v) {
		if (v != null) {
			for (KeyUsageBit kub : KeyUsageBit.values()) {
				if (kub.getValue().equals(v)) {
					return kub;
				}
			}
		}
		return null;
	}

	public static String print(KeyUsageBit v) {
		if (v != null) {
			return v.getValue();
		}
		return null;
	}

}
