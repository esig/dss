package eu.europa.esig.dss.pades.signature.visible;

import java.io.InputStream;

/**
 * An InputStream wrapper for an image, and its horizontal and vertical resolution
 * 
 * @author pakeyser
 *
 */
public class ImageAndResolution {
	private int xDpi;

	private int yDpi;

	private InputStream inputStream;

	public ImageAndResolution(InputStream inputStream, int xDpi, int yDpi) {
		this.xDpi = xDpi;
		this.yDpi = yDpi;
		this.inputStream = inputStream;
	}

	public int getxDpi() {
		return xDpi;
	}

	public int getyDpi() {
		return yDpi;
	}

	public float toXInch(float x) {
		return x / (xDpi);
	}

	public float toXPoint(float x) {
		return toXInch(x) * 72f;
	}

	public float toYInch(float y) {
		return y / (yDpi);
	}

	public float toYPoint(float y) {
		return toYInch(y) * 72f;
	}

	@Override
	public String toString() {
		return "Resolution [xDpi=" + xDpi + ", yDpi=" + yDpi + "]";
	}

	public InputStream getInputStream() {
		return inputStream;
	}

}
