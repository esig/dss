/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.visible;

/**
 * Contains util methods for DPI processing
 *
 */
public class DPIUtils {

	/** Default text DPI */
	private static final int DPI = 300;

	/** Default page DPI */
	private static final int PDF_DEFAULT_DPI = 72;

	/**
	 * Default constructor
	 */
	private DPIUtils() {
	}

	/**
	 * Returns text DPI (300)
	 *
	 * @return text dpi (300)
	 */
	public static int getTextDpi() {
		return DPI;
	}

	/**
	 * Gets the given or default of none is provided
	 *
	 * @param dpi {@link Integer}
	 * @return dpi
	 */
	public static int getDpi(Integer dpi) {
		int result = DPI;
		if (dpi != null && dpi > 0) {
			result = dpi;
		}
		return result;
	}

	/**
	 * Converts to full quality with the given DPI respectively to a page DPI
	 *
	 * @param x the value to convert
	 * @param dpi the dpi to use
	 * @return converted value
	 */
	public static float computeProperSize(float x, float dpi) {
		return x * dpi / PDF_DEFAULT_DPI;
	}

	/**
	 * Converts the value to be displayed on a page
	 *
	 * @param dpi {@link Integer} of the image/text
	 * @return the converted page DPI
	 */
	public static float getPageScaleFactor(Integer dpi) {
		float floatDpi = getDpi(dpi);
		return PDF_DEFAULT_DPI / floatDpi;
	}

}
