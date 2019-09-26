package eu.europa.esig.dss.tsl.job;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;

public class EmptyRefreshTest {

	@Test
	public void test() {
		TLValidationJob job = new TLValidationJob();
		NullPointerException exception = assertThrows(NullPointerException.class, () -> job.offlineRefresh());
		assertEquals("The offlineLoader must be defined!", exception.getMessage());
		assertThrows(NullPointerException.class, () -> job.onlineRefresh());

		job.setOfflineDataLoader(new FileCacheDataLoader());

		job.offlineRefresh();
	}

}
