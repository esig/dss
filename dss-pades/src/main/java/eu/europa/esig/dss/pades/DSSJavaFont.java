package eu.europa.esig.dss.pades;

import java.awt.Font;
import java.io.InputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;

public class DSSJavaFont extends AbstractDSSFont {

	private static final Logger LOG = LoggerFactory.getLogger(DSSJavaFont.class);
	
	private static final int DEFAULT_FONT_STYLE = Font.PLAIN;
	
	public DSSJavaFont(Font javaFont) {
		this.javaFont = javaFont;
		this.size = javaFont.getSize();
	}
	
	public DSSJavaFont(String fontName) {
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, (int) DEFAULT_TEXT_SIZE);
	}
	
	public DSSJavaFont(String fontName, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, DEFAULT_FONT_STYLE, size);
	}
	
	public DSSJavaFont(String fontName, int style, int size) {
		this.size = size;
		this.javaFont = new Font(fontName, style, size);
	}

	@Override
	public InputStream getInputStream() {
		throw new DSSException("InputStream cannot be obtained from DSSJavaFont. Please use DSSFileFont implementation.");
	}

	@Override
	public String getName() {
		return javaFont.getFontName();
	}

	@Override
	public void setSize(float size) {
		this.size = size;
		this.javaFont = javaFont.deriveFont(size);
	}

	@Override
	public boolean isLogicalFont() {
		LOG.warn("The given font is logical (one of standart 14 fonts) and cannot be embedded to a PDF document. "
				+ "Please, use DSSFileFont implementation to get the document compatible with the PDF/A standard.");
		return true;
	}

}
