package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.MaskGenerationFunction;

public class MaskGenerationFunctionParser {

	private MaskGenerationFunctionParser() {
	}

	public static MaskGenerationFunction parse(String v) {
		if (v != null) {
			return MaskGenerationFunction.valueOf(v);
		}
		return null;
	}

	public static String print(MaskGenerationFunction v) {
		if (v != null) {
			return v.name();
		}
		return null;
	}

}
