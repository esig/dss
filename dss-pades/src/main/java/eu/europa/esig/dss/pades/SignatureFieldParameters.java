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
package eu.europa.esig.dss.pades;

import java.io.Serializable;

/**
 * Parameters which allow to create a new signature field in a PDF document
 */
@SuppressWarnings("serial")
public class SignatureFieldParameters implements Serializable {

	/* Signature field name (optional) */
	private String name;
	/* Page number where the signature field is added */
	private int page = PAdESUtils.DEFAULT_FIRST_PAGE;
	/* Coordinate X where to add the signature field (origin is bottom/left corner) */
	private float originX;
	/* Coordinate Y where to add the signature field (origin is bottom/left corner) */
	private float originY;
	/* Signature field width */
	private float width;
	/* Signature field height */
	private float height;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getPage() {
		return page;
	}

	public void setPage(int page) {
		this.page = page;
	}

	public float getOriginX() {
		return originX;
	}

	public void setOriginX(float originX) {
		this.originX = originX;
	}

	public float getOriginY() {
		return originY;
	}

	public void setOriginY(float originY) {
		this.originY = originY;
	}

	public float getWidth() {
		return width;
	}

	public void setWidth(float width) {
		this.width = width;
	}

	public float getHeight() {
		return height;
	}

	public void setHeight(float height) {
		this.height = height;
	}

	@Override
	public String toString() {
		return "SignatureFieldParameters [name=" + name + ", page=" + page + ", originX=" + originX + ", originY="
				+ originY + ", width=" + width + ", height=" + height + "]";
	}

}
