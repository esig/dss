package eu.europa.esig.dss.tsl.predicates.othertslpointer;

import java.util.Map;
import java.util.Objects;

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public class TypeOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2#}TSLType";

	private final String expectedTSLType;

	public TypeOtherTSLPointer(String expectedTSLType) {
		Objects.requireNonNull(expectedTSLType, "Expected TSLType must be defined");
		this.expectedTSLType = expectedTSLType;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String tslType = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return expectedTSLType.equalsIgnoreCase(tslType);
	}

}
