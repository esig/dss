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

import eu.europa.esig.dss.tsl.cache.CachedResult;

public class StateMachineTest {

	@Test
	public void testEmpty() throws Exception {
		CachedEntry<MockCachedResult> cachedEntry = new CachedEntry<MockCachedResult>();
		Date emptyStateDate = cachedEntry.getLastSuccessDate();
		assertNotNull(emptyStateDate);
		assertNull(cachedEntry.getCachedResult());
		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());
		assertTrue(cachedEntry.isRefreshNeeded());

		IllegalStateException e = assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertEquals("Transition from 'REFRESH_NEEDED' to 'SYNCHRONIZED' is not allowed", e.getMessage());

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());

		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());
		assertEquals(emptyStateDate, cachedEntry.getLastSuccessDate());

		assertThrows(NullPointerException.class, () -> cachedEntry.update(null));

		cachedEntry.update(new MockCachedResult(5));

		assertFalse(cachedEntry.isRefreshNeeded());

		// cannot update twice
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(new MockCachedResult(7)));

		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		Date desynchonizedStateDate = cachedEntry.getLastSuccessDate();
		assertNotEquals(emptyStateDate, desynchonizedStateDate);
		assertEquals(5, cachedEntry.getCachedResult().integer);

		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());

		Thread.sleep(1);
		cachedEntry.sync();

		assertEquals(CacheStateEnum.SYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getLastSuccessDate());

		// must be expired first
		assertThrows(IllegalStateException.class, () -> cachedEntry.update(new MockCachedResult(7)));
		assertEquals(5, cachedEntry.getCachedResult().integer);

		cachedEntry.expire();

		assertTrue(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStateEnum.REFRESH_NEEDED, cachedEntry.getCurrentState());

		cachedEntry.update(new MockCachedResult(7));

		assertFalse(cachedEntry.isRefreshNeeded());

		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertNotEquals(desynchonizedStateDate, cachedEntry.getLastSuccessDate());
		assertEquals(7, cachedEntry.getCachedResult().integer);

		cachedEntry.sync();

		cachedEntry.expire();
		cachedEntry.error(new CachedException(new IllegalArgumentException("Unable to parse")));
		assertNotNull(cachedEntry.getLastSuccessDate());

		assertTrue(cachedEntry.isError());
		assertNotNull(cachedEntry.getExceptionMessage());
		assertNotNull(cachedEntry.getExceptionStackTrace());
		assertNull(cachedEntry.getCachedResult());

		cachedEntry.toBeDeleted();
		assertEquals(CacheStateEnum.TO_BE_DELETED, cachedEntry.getCurrentState());
		assertThrows(IllegalStateException.class, () -> cachedEntry.sync());
		assertThrows(IllegalStateException.class, () -> cachedEntry.toBeDeleted());
		assertThrows(IllegalStateException.class, () -> cachedEntry.expire());
	}

	@Test
	public void testDesynchro() {
		CachedEntry<MockCachedResult> cachedEntry = new CachedEntry<MockCachedResult>(new MockCachedResult(8));
		assertEquals(CacheStateEnum.DESYNCHRONIZED, cachedEntry.getCurrentState());
		assertEquals(8, cachedEntry.getCachedResult().integer);
		assertNotNull(cachedEntry.getLastSuccessDate());
	}
	
	private class MockCachedResult implements CachedResult {
		
		private Integer integer;
		
		MockCachedResult(Integer integer) {
			this.integer = integer;
		}
		
	}

}
