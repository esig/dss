package eu.europa.ec.markt.dss.parameter;

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
