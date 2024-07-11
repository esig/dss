/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.converter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.awt.Color;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.ws.dto.RemoteColor;

class ColorConverterTest {

	@Test
	void convert() {
		RemoteColor remoteColor = ColorConverter.toRemoteColor(Color.WHITE);
		Color color = ColorConverter.toColor(remoteColor);
		assertEquals(Color.WHITE, color);
	}

	@Test
	void convertWithAlpha() {
		Color original = new Color(10, 10, 10, 10);
		RemoteColor remoteColor = ColorConverter.toRemoteColor(original);
		Color color = ColorConverter.toColor(remoteColor);
		assertEquals(original, color);
	}

	@Test
	void convertNull() {
		assertNull(ColorConverter.toColor(null));
		assertNull(ColorConverter.toColor(new RemoteColor()));
		assertNull(ColorConverter.toRemoteColor(null));
	}

	@Test
	void convertNotValid() {
		RemoteColor remoteColor = new RemoteColor(-1, 10, 10);
		assertThrows(IllegalArgumentException.class, () -> ColorConverter.toColor(remoteColor));

		RemoteColor remoteColorWithAlpha = new RemoteColor(10, 10, 10, -1);
		assertThrows(IllegalArgumentException.class, () -> ColorConverter.toColor(remoteColorWithAlpha));
	}

}
