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
package eu.europa.esig.dss.pdf.visible;

import java.awt.Graphics2D;
import java.awt.RenderingHints;

public class CommonDrawerUtils {

	private static final int DPI = 300;
	protected static final int PDF_DEFAULT_DPI = 72;
	
	private CommonDrawerUtils() {
	}
	
	public static int getTextDpi() {
		return DPI;
	}

	public static int getDpi(Integer dpi) {
		int result = DPI;
		if (dpi != null && dpi.intValue() > 0) {
			result = dpi.intValue();
		}
		return result;
	}
	
	public static float toDpiAxisPoint(float x, float dpi) {
		return x * PDF_DEFAULT_DPI / dpi;
	}
	
	public static float computeProperSize(float x, float dpi) {
		return x * dpi / PDF_DEFAULT_DPI;
	}

	public static float getRation(Integer dpi) {
		float floatDpi = getDpi(dpi);
		return floatDpi / PDF_DEFAULT_DPI;
	}
	
	public static float getPageScaleFactor(Integer dpi) {
		float floatDpi = getDpi(dpi);
		return PDF_DEFAULT_DPI / floatDpi;
	}
	
	public static float getTextScaleFactor(Integer dpi) {
		float floatDpi = getDpi(dpi);
		return DPI / floatDpi;
	}

	public static void initRendering(Graphics2D g) {
		g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
		g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		g.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION, RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
	}

}
