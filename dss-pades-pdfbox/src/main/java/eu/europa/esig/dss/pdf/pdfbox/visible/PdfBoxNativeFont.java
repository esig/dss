package eu.europa.esig.dss.pdf.pdfbox.visible;

import java.awt.Font;

import org.apache.pdfbox.pdmodel.font.PDFont;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;

public class PdfBoxNativeFont extends AbstractDSSFont implements DSSNativeFont<PDFont> {
	
	private final PDFont pdFont;
	
	public PdfBoxNativeFont(PDFont pdFont) {
		this.pdFont = pdFont;
	}

	@Override
	public PDFont getFont() {
		return pdFont;
	}

	@Override
	public Font getJavaFont() {
		throw new DSSException("PdfBoxNativeFont.class can be used only with PdfBoxNativeObjectFactory!");
	}

}
