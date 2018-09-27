package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.policy.Context;

public final class ContextParser {

	private ContextParser() {
	}

	public static Context parse(String v) {
		if (v != null) {
			return Context.valueOf(v);
		}
		return null;
	}

	public static String print(Context v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
