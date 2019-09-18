package eu.europa.esig.dss.tsl.function;

import java.util.function.Predicate;

/**
 * This class checks if the String is an official registration identifier as
 * specified in ETSI TS 119 612 (ch 5.4.2)
 */
public class OfficialRegistrationIdentifierPredicate implements Predicate<String> {

	// Legal Person
	private static final String VAT = "VAT";
	private static final String NTR = "NTR";

	// Natural Person
	private static final String PAS = "PAS";
	private static final String IDC = "IDC";
	private static final String PNO = "PNO";
	private static final String TIN = "TIN";

	@Override
	public boolean test(String t) {
		return t != null && (isLegalPerson(t) || isNaturalPerson(t));
	}

	private boolean isLegalPerson(String t) {
		return t.startsWith(VAT) || t.startsWith(NTR);
	}

	private boolean isNaturalPerson(String t) {
		return t.startsWith(PAS) || t.startsWith(IDC) || t.startsWith(PNO) || t.startsWith(TIN);
	}

}
