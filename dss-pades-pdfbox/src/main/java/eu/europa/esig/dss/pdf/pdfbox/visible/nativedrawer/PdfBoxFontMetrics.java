package eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer;

import java.io.IOException;

import org.apache.pdfbox.pdmodel.font.PDFont;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.visible.AbstractFontMetrics;

public class PdfBoxFontMetrics extends AbstractFontMetrics {
	
	private final PDFont pdFont;
	
	public PdfBoxFontMetrics(PDFont pdFont) {
		this.pdFont = pdFont;
	}

	@Override
	public float getWidth(String str, float size) {
		try {
			return pdFont.getStringWidth(str) / 1000 * size;
		} catch (IOException e) {
			throw new DSSException("Unable to compute string width!");
		}
	}

	@Override
	public float getHeight(String str, float size) {
		try {
			return pdFont.getBoundingBox().getHeight() / 1000 * size;
		} catch (IOException e) {
			throw new DSSException("Unable to compute string height!");
		}
	}

}
