package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.policy.rules.Indication;

public class IndicationParser {

	public static Indication parse(String v) {
		return Indication.valueOf(v);
	}

	public static String print(Indication v) {
		return v.name();
	}

}
