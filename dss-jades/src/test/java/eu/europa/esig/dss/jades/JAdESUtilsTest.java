package eu.europa.esig.dss.jades;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class JAdESUtilsTest {
	
	@Test
	public void isUrlSafePayloadTest() {
		assertTrue(JAdESUtils.isUrlSafePayload(""));
		assertTrue(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsbyBXb3JsZCEiDQp9"));
		assertTrue(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsbyBXb3JsZCEiDQp9???!!!"));
		assertTrue(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb yBXb3JsZCEiDQp9"));
		assertFalse(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb.yBXb3JsZCEiDQp9"));
		assertFalse(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb\nyBXb3JsZCEiDQp9"));
		assertFalse(JAdESUtils.isUrlSafePayload("ew0KICAgICJ0aXRsZSI6ICJIZWxsb\ryBXb3JsZCEiDQp9"));
		assertFalse(JAdESUtils.isUrlSafePayload("."));
		assertFalse(JAdESUtils.isUrlSafePayload("..."));
	}

}
