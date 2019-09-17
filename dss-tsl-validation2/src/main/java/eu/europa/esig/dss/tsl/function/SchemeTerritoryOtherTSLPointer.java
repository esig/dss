package eu.europa.esig.dss.tsl.function;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;

public class SchemeTerritoryOtherTSLPointer extends AbstractOtherTSLPointerPredicate {

	private static final String EXPECTED_TAG_NAME = "{http://uri.etsi.org/02231/v2#}SchemeTerritory";

	private final Set<String> countyCodes;

	public SchemeTerritoryOtherTSLPointer(String countryCode) {
		this(Collections.singleton(countryCode));
	}

	public SchemeTerritoryOtherTSLPointer(Set<String> countryCodes) {
		this.countyCodes = countryCodes;
	}

	@Override
	public boolean test(OtherTSLPointerType o) {
		Map<String, Object> extractAdditionalInformation = extractAdditionalInformation(o);
		String schemeTerritory = (String) extractAdditionalInformation.get(EXPECTED_TAG_NAME);
		return countyCodes.contains(schemeTerritory);
	}

}
