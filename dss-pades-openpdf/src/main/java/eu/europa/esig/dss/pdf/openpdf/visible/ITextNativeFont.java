package eu.europa.esig.dss.pdf.openpdf.visible;

import java.awt.Font;

import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.DefaultFontMapper;

import eu.europa.esig.dss.pades.AbstractDSSFont;
import eu.europa.esig.dss.pades.DSSNativeFont;

public class ITextNativeFont extends AbstractDSSFont implements DSSNativeFont<BaseFont> {
	
	private final BaseFont baseFont;
	
	public ITextNativeFont(BaseFont baseFont) {
		this.baseFont = baseFont;
	}

	@Override
	public BaseFont getFont() {
		return baseFont;
	}

	@Override
	public Font getJavaFont() {
		DefaultFontMapper fontMapper = new DefaultFontMapper();
		return fontMapper.pdfToAwt(baseFont, (int)size);
	}

}
