package eu.europa.esig.dss.tsl.function;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class OfficialRegistrationIdentifierPredicateTest {

	private OfficialRegistrationIdentifierPredicate predicate = new OfficialRegistrationIdentifierPredicate();

	@Test
	public void testNull() {
		assertFalse(predicate.test(null));
	}

	@Test
	public void testFalse() {
		assertFalse(predicate.test("ABC12"));
	}

	@Test
	public void testTrue() {
		assertTrue(predicate.test("VAT123"));
		assertTrue(predicate.test("TIN123"));
	}

}
