package eu.europa.esig.dss.tsl.function;

import java.util.Objects;
import java.util.function.Predicate;

import eu.europa.esig.trustedlist.jaxb.tsl.NonEmptyMultiLangURIType;

public final class SchemeInformationURIByLang implements Predicate<NonEmptyMultiLangURIType> {

	private final String lang;

	public SchemeInformationURIByLang(String lang) {
		Objects.requireNonNull(lang);
		this.lang = lang;
	}

	@Override
	public boolean test(NonEmptyMultiLangURIType schemeInformationURI) {
		return lang.equals(schemeInformationURI.getLang());
	}

}
