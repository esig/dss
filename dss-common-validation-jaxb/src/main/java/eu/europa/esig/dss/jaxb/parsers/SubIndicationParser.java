package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.validation.policy.rules.SubIndication;

public class SubIndicationParser {

	public static SubIndication parse(String v) {
		return SubIndication.forName(v);
	}

	public static String print(SubIndication v) {
		return v.name();
	}

}
