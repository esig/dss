package eu.europa.esig.dss.tsl.function;

import java.util.function.Predicate;

/**
 * Predicate which filter official registration identifiers
 */
public class TradeNamePredicate implements Predicate<String> {

	private OfficialRegistrationIdentifierPredicate registrationIdentifier = new OfficialRegistrationIdentifierPredicate();

	@Override
	public boolean test(String t) {
		return t != null && !registrationIdentifier.test(t);
	}

}
