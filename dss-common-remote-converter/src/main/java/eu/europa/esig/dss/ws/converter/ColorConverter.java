package eu.europa.esig.dss.ws.converter;

import java.awt.Color;

import eu.europa.esig.dss.ws.dto.RemoteColor;

public final class ColorConverter {

	private ColorConverter() {
	}

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
