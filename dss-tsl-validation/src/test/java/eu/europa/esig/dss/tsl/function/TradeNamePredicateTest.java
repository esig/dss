package eu.europa.esig.dss.tsl.function;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TradeNamePredicateTest {

	private TradeNamePredicate predicate = new TradeNamePredicate();

	@Test
	public void testNull() {
		assertFalse(predicate.test(null));
	}

	@Test
	public void testTrue() {
		assertTrue(predicate.test("ABC12"));
	}

	@Test
	public void testFalse() {
		assertFalse(predicate.test("VAT123"));
		assertFalse(predicate.test("TIN123"));
	}

}
