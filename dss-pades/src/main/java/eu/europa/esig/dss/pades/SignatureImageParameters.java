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

import java.io.File;

/**
 * Parameters for a visible signature creation
 *
 */
public class SignatureImageParameters {

	public static final int DEFAULT_PAGE = 1;

	/**
	 * This variable contains the image to use (company logo,...)
	 */
	private File image;

	/**
	 * This variable defines the page where the image will appear (1st page by
	 * default)
	 */
	private int page = DEFAULT_PAGE;

	/**
	 * This variable defines the position of the image in the PDF page (X axis)
	 */
	private float xAxis;

	/**
	 * This variable defines the position of the image in the PDF page (Y axis)
	 */
	private float yAxis;

	/**
	 * This variable is use to defines the text to generate on the image
	 */
	private SignatureImageTextParameters textParameters;

	public File getImage() {
		return image;
	}

	public void setImage(File image) {
		this.image = image;
	}

	public float getxAxis() {
		return xAxis;
	}

	public void setxAxis(float xAxis) {
		this.xAxis = xAxis;
	}

	public float getyAxis() {
		return yAxis;
	}

	public void setyAxis(float yAxis) {
		this.yAxis = yAxis;
	}

	public int getPage() {
		return page;
	}

	public void setPage(int page) {
		this.page = page;
	}

	public SignatureImageTextParameters getTextParameters() {
		return textParameters;
	}

	public void setTextParameters(SignatureImageTextParameters textParameters) {
		this.textParameters = textParameters;
	}

}
