package eu.europa.esig.dss.pades.signature.visible.nativedrawer;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.pades.signature.visible.PAdESVisibleSignatureWithJavaFont;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;

public class PdfBoxNativeDrawerPAdESTextVisibleSignatureTest extends PAdESVisibleSignatureWithJavaFont {
	
	@BeforeEach
	@Override
	public void init() throws Exception {
		super.init();
		PdfObjFactory.setInstance(new PdfBoxNativeObjectFactory());
	}

}
