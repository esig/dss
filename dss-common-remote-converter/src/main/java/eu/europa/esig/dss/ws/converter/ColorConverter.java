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

import eu.europa.esig.dss.ws.dto.RemoteColor;

import java.awt.Color;

/**
 * Contains utils to convert {@code Color} to {@code RemoteColor} object and vice versa
 */
public final class ColorConverter {

	private ColorConverter() {
	}

	/**
	 * Converts {@code Color} to {@code RemoteColor} object
	 *
	 * @param color {@link Color} to convert
	 * @return {@link RemoteColor}
	 */
	public static RemoteColor toRemoteColor(Color color) {
		if (color == null) {
			return null;
		}
		RemoteColor remote = new RemoteColor();
		remote.setRed(color.getRed());
		remote.setGreen(color.getGreen());
		remote.setBlue(color.getBlue());
		remote.setAlpha(color.getAlpha());
		return remote;
	}

	/**
	 * Converts {@code RemoteColor} to {@code Color} object
	 *
	 * @param remoteColor {@link RemoteColor} to convert
	 * @return {@link Color}
	 */
	public static Color toColor(RemoteColor remoteColor) {
		if (remoteColor == null) {
			return null;
		}
		if (isRGB(remoteColor)) {
			return new Color(remoteColor.getRed(), remoteColor.getGreen(), remoteColor.getBlue());
		} else if (isRGBA(remoteColor)) {
			return new Color(remoteColor.getRed(), remoteColor.getGreen(), remoteColor.getBlue(), remoteColor.getAlpha());
		}
		return null;
	}

	private static boolean isRGB(RemoteColor colorValues) {
		return (colorValues.getRed() != null) && (colorValues.getGreen() != null) && (colorValues.getBlue() != null) && (colorValues.getAlpha() == null);
	}

	private static boolean isRGBA(RemoteColor colorValues) {
		return (colorValues.getRed() != null) && (colorValues.getGreen() != null) && (colorValues.getBlue() != null) && (colorValues.getAlpha() != null);
	}

}
