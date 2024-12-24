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
package eu.europa.esig.dss.ws.dto;

import java.io.Serializable;

/**
 * DTO for a {@code Color} object
 */
@SuppressWarnings("serial")
public class RemoteColor implements Serializable {

	/** The red color layer value */
	private Integer red;

	/** The green color layer value */
	private Integer green;

	/** The blue color layer value */
	private Integer blue;

	/** The blue color layer value */
	private Integer alpha;

	/**
	 * The empty constructor
	 */
	public RemoteColor() {
	}

	/**
	 * The default constructor without alpha layer
	 *
	 * @param red R color value
	 * @param green G color value
	 * @param blue B color value
	 */
	public RemoteColor(int red, int green, int blue) {
		this.red = red;
		this.green = green;
		this.blue = blue;
	}

	/**
	 * The default constructor with alpha layer
	 *
	 * @param red R color value
	 * @param green G color value
	 * @param blue B color value
	 * @param alpha alpha layer value
	 */
	public RemoteColor(Integer red, Integer green, Integer blue, Integer alpha) {
		this.red = red;
		this.green = green;
		this.blue = blue;
		this.alpha = alpha;
	}

	/**
	 * Gets red color value
	 *
	 * @return {@link Integer}
	 */
	public Integer getRed() {
		return red;
	}

	/**
	 * Sets red color value
	 *
	 * @param red {@link Integer}
	 */
	public void setRed(Integer red) {
		this.red = red;
	}

	/**
	 * Gets green color value
	 *
	 * @return {@link Integer}
	 */
	public Integer getGreen() {
		return green;
	}

	/**
	 * Sets green color value
	 *
	 * @param green {@link Integer}
	 */
	public void setGreen(Integer green) {
		this.green = green;
	}

	/**
	 * Gets blue color value
	 *
	 * @return {@link Integer}
	 */
	public Integer getBlue() {
		return blue;
	}

	/**
	 * Sets blue color value
	 *
	 * @param blue {@link Integer}
	 */
	public void setBlue(Integer blue) {
		this.blue = blue;
	}

	/**
	 * Gets alpha layer value
	 *
	 * @return {@link Integer}
	 */
	public Integer getAlpha() {
		return alpha;
	}

	/**
	 * Sets alpha layer value
	 *
	 * @param alpha {@link Integer}
	 */
	public void setAlpha(Integer alpha) {
		this.alpha = alpha;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((alpha == null) ? 0 : alpha.hashCode());
		result = prime * result + ((blue == null) ? 0 : blue.hashCode());
		result = prime * result + ((green == null) ? 0 : green.hashCode());
		result = prime * result + ((red == null) ? 0 : red.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RemoteColor other = (RemoteColor) obj;
		if (alpha == null) {
			if (other.alpha != null) {
				return false;
			}
		} else if (!alpha.equals(other.alpha)) {
			return false;
		}
		if (blue == null) {
			if (other.blue != null) {
				return false;
			}
		} else if (!blue.equals(other.blue)) {
			return false;
		}
		if (green == null) {
			if (other.green != null) {
				return false;
			}
		} else if (!green.equals(other.green)) {
			return false;
		}
		if (red == null) {
			if (other.red != null) {
				return false;
			}
		} else if (!red.equals(other.red)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "RemoteColor [red=" + red + ", green=" + green + ", blue=" + blue + ", alpha=" + alpha + "]";
	}

}
