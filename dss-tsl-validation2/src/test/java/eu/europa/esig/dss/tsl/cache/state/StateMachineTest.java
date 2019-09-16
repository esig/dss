package eu.europa.esig.dss.tsl.cache.state;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.Test;

public class StateMachineTest {

	@Test
	public void testEmpty() {
		CachedEntry<Integer> cachedEntry = new CachedEntry<Integer>();
		Date emptyStateDate = cachedEntry.getCurrentStateDate();
		assertNotNull(emptyStateDate);
		assertNull(cachedEntry.getCachedObject());
		assertEquals(CacheStates.EMPTY, cachedEntry.getCurrentState());
		assertTrue(cachedEntry.isRefreshNeeded());

		IllegalStateException e = assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertEquals("Transition from 'EMPTY' to 'SYNCHRONIZED' is not allowed", e.getMessage());

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.expire());

		assertEquals(CacheStates.EMPTY, cachedEntry.getCurrentState());
		assertEquals(emptyStateDate, cachedEntry.getCurrentStateDate());

		assertThrows(NullPointerException.class, () -> cachedEntry.update(null));

		cachedEntry.update(5);

		assertFalse(cachedEntry.isRefreshNeeded());

		// cannot update twice
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(7));

		assertEquals(CacheStates.DESYNCHRONIZED, cachedEntry.getCurrentState());
		Date desynchonizedStateDate = cachedEntry.getCurrentStateDate();
		assertNotEquals(emptyStateDate, desynchonizedStateDate);
		assertEquals(5, cachedEntry.getCachedObject());

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.expire());

		cachedEntry.sync();

		assertEquals(CacheStates.SYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getCurrentStateDate());

		// must be expired first
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(7));
		assertEquals(5, cachedEntry.getCachedObject());

		cachedEntry.expire();

		assertTrue(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStates.EXPIRED, cachedEntry.getCurrentState());

		cachedEntry.update(7);

		assertFalse(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStates.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getCurrentStateDate());
		assertEquals(7, cachedEntry.getCachedObject());

		cachedEntry.sync();
		
		cachedEntry.toBeDeleted();
		assertEquals(CacheStates.TO_BE_DELETED, cachedEntry.getCurrentState());
		assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.expire());
	}

	@Test
	public void testDesynchro() {
		CachedEntry<Integer> cachedEntry = new CachedEntry<Integer>(8);
		assertEquals(CacheStates.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertEquals(8, cachedEntry.getCachedObject());
		assertNotNull(cachedEntry.getCurrentStateDate());
	}

}
