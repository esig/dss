package eu.europa.esig.dss.tsl.function;

import java.util.Map;
import java.util.Objects;

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public class MimetypeOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2/additionaltypes#}MimeType";

	private final String expectedMimeType;

	public MimetypeOtherTSLPointer(String expectedMimeType) {
		Objects.requireNonNull(expectedMimeType, "Expected MimeType must be defined");
		this.expectedMimeType = expectedMimeType;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String mimeType = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return expectedMimeType.equalsIgnoreCase(mimeType);
	}

}
