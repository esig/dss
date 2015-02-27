package eu.europa.ec.markt.dss.parameter;

import java.awt.Color;
import java.awt.Font;

/**
 * This class allows to custom text generation in the PAdES visible signature
 *
 */
public class SignatureImageTextParameters {

	public static final Font DEFAULT_FONT = new Font("serif", Font.PLAIN, 12);
	public static final Color DEFAUT_TEXT_COLOR = Color.BLACK;
	public static final Color DEFAULT_BACKGROUND_COLOR = Color.WHITE;

	/**
	 * Enum to define where to add the signer name on the image
	 */
	public enum SignerPosition {
		TOP, BOTTOM, RIGHT, LEFT
	}

	/**
	 * This variable allows to add signer name on the image (by default, LEFT)
	 */
	private SignerPosition signerNamePosition = SignerPosition.LEFT;

	/**
	 * This variable defines the text to sign
	 */
	private String text;

	/**
	 * This variable defines the font to use when the signerNamePosition is not
	 * NONE)
	 */
	private Font font = DEFAULT_FONT;

	/**
	 * This variable defines the text color to use when the signerNamePosition
	 * is not NONE (default is BLACK)
	 */
	private Color textColor = DEFAUT_TEXT_COLOR;

	/**
	 * This variable defines the text color to use when the signerNamePosition
	 * is not NONE (default is WHITE)
	 */
	private Color backgroundColor = DEFAULT_BACKGROUND_COLOR;

	public SignerPosition getSignerNamePosition() {
		return signerNamePosition;
	}

	public void setSignerNamePosition(SignerPosition signerNamePosition) {
		this.signerNamePosition = signerNamePosition;
	}

	public Font getFont() {
		return font;
	}

	public void setFont(Font font) {
		this.font = font;
	}

	public Color getTextColor() {
		return textColor;
	}

	public void setTextColor(Color textColor) {
		this.textColor = textColor;
	}

	public Color getBackgroundColor() {
		return backgroundColor;
	}

	public void setBackgroundColor(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

}
