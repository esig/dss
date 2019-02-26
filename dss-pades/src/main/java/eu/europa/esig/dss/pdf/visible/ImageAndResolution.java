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

import java.io.InputStream;

import eu.europa.esig.dss.DSSDocument;

/**
 * An InputStream wrapper for an image, and its horizontal and vertical resolution
 * 
 * @author pakeyser
 *
 */
public class ImageAndResolution {

	private int xDpi;
	private int yDpi;
	private DSSDocument image;

	public ImageAndResolution(DSSDocument image, int xDpi, int yDpi) {
		this.xDpi = xDpi;
		this.yDpi = yDpi;
		this.image = image;
	}

	public int getxDpi() {
		return xDpi;
	}

	public int getyDpi() {
		return yDpi;
	}

	public float toXPoint(float x) {
		return CommonDrawerUtils.toDpiAxisPoint(x, xDpi);
	}

	public float toYPoint(float y) {
		return CommonDrawerUtils.toDpiAxisPoint(y, yDpi);
	}

	@Override
	public String toString() {
		return "Resolution [xDpi=" + xDpi + ", yDpi=" + yDpi + "]";
	}

	public InputStream getInputStream() {
		return image.openStream();
	}

}
