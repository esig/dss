package eu.europa.esig.trustedlist.parsers;

import eu.europa.esig.trustedlist.enums.Assert;

public final class AssertParser {

	private AssertParser() {
	}

	public static Assert parse(String v) {
		if (v != null) {
			for (Assert a : Assert.values()) {
				if (a.getValue().equals(v)) {
					return a;
				}
			}
		}
		return null;
	}

	public static String print(Assert a) {
		if (a != null) {
			return a.getValue();
		}
		return null;
	}

}
