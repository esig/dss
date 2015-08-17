package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertTrue;

import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.collections.MapUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.TSLValidationModel;

public class LOTLLoaderTest {

	private static final Logger logger = LoggerFactory.getLogger(LOTLLoaderTest.class);

	@Test
	public void loadLotlAndTsl() {
		LOTLLoader loader = new LOTLLoader();
		loader.setDataLoader(new CommonsDataLoader());
		Map<String, TSLValidationModel> map = loader.loadLotlAndTsl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");

		assertTrue(MapUtils.isNotEmpty(map));

		for (Entry<String, TSLValidationModel> entry : map.entrySet()) {
			logger.info(entry.getKey() + " " + entry.getValue());
		}
	}
}
