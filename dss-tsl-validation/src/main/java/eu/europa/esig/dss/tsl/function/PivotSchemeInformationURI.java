package eu.europa.esig.dss.tsl.function;

import java.util.function.Predicate;

import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

public final class PivotSchemeInformationURI implements Predicate<NonEmptyMultiLangURIType> {

	/**
	 * Defined condition in (draft) ETSI TS 119 615
	 */
	private static final String PIVOT_SUFFIX = ".xml";

	@Override
	public boolean test(NonEmptyMultiLangURIType t) {
		if (t != null && t.getValue() != null) {
			return t.getValue().endsWith(PIVOT_SUFFIX);
		}
		return false;
	}

}
