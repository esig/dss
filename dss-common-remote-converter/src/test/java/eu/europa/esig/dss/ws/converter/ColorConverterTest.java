package eu.europa.esig.dss.ws.converter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.awt.Color;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.ws.dto.RemoteColor;

public class ColorConverterTest {

	@Test
	public void convert() {
		RemoteColor remoteColor = ColorConverter.toRemoteColor(Color.WHITE);
		Color color = ColorConverter.toColor(remoteColor);
		assertEquals(Color.WHITE, color);
	}

	@Test
	public void convertWithAlpha() {
		Color original = new Color(10, 10, 10, 10);
		RemoteColor remoteColor = ColorConverter.toRemoteColor(original);
		Color color = ColorConverter.toColor(remoteColor);
		assertEquals(original, color);
	}

	@Test
	public void convertNull() {
		assertNull(ColorConverter.toColor(null));
		assertNull(ColorConverter.toColor(new RemoteColor()));
		assertNull(ColorConverter.toRemoteColor(null));
	}

	@Test
	public void convertNotValid() {
		RemoteColor remoteColor = new RemoteColor(-1, 10, 10);
		assertThrows(IllegalArgumentException.class, () -> ColorConverter.toColor(remoteColor));

		RemoteColor remoteColorWithAlpha = new RemoteColor(10, 10, 10, -1);
		assertThrows(IllegalArgumentException.class, () -> ColorConverter.toColor(remoteColorWithAlpha));
	}

}
