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
		Date emptyStateDate = cachedEntry.getLastSuccessDate();
		assertNotNull(emptyStateDate);
		assertNull(cachedEntry.getCachedObject());
		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());
		assertTrue(cachedEntry.isRefreshNeeded());

		IllegalStateException e = assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertEquals("Transition from 'REFRESH_NEEDED' to 'SYNCHRONIZED' is not allowed", e.getMessage());

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.refreshNeeded());

		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());
		assertEquals(emptyStateDate, cachedEntry.getLastSuccessDate());

		assertThrows(NullPointerException.class, () -> cachedEntry.update(null));

		cachedEntry.update(5);

		assertFalse(cachedEntry.isRefreshNeeded());

		// cannot update twice
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(7));

		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		Date desynchonizedStateDate = cachedEntry.getLastSuccessDate();
		assertNotEquals(emptyStateDate, desynchonizedStateDate);
		assertEquals(5, cachedEntry.getCachedObject());

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.refreshNeeded());

		cachedEntry.sync();

		assertEquals(CacheStateEnum.SYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getLastSuccessDate());

		// must be expired first
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(7));
		assertEquals(5, cachedEntry.getCachedObject());

		cachedEntry.refreshNeeded();

		assertTrue(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());

		cachedEntry.update(7);

		assertFalse(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getLastSuccessDate());
		assertEquals(7, cachedEntry.getCachedObject());

		cachedEntry.sync();
		
		cachedEntry.refreshNeeded();
		cachedEntry.error("Unable to parse");
		assertNotNull(cachedEntry.getLastSuccessDate());

		cachedEntry.toBeDeleted();
		assertEquals(CacheStateEnum.TO_BE_DELETED, cachedEntry.getCurrentState());
		assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.refreshNeeded());
	}

	@Test
	public void testDesynchro() {
		CachedEntry<Integer> cachedEntry = new CachedEntry<Integer>(8);
		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertEquals(8, cachedEntry.getCachedObject());
		assertNotNull(cachedEntry.getLastSuccessDate());
	}

}
