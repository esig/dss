package eu.europa.esig.dss.pades.signature.visible.nativedrawer;

import org.junit.Before;

import eu.europa.esig.dss.pades.signature.visible.PAdESVisibleSignatureWithJavaFont;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;

public class PdfBoxNativeDrawerPAdESTextVisibleSignatureTest extends PAdESVisibleSignatureWithJavaFont {
	
	@Before
	@Override
	public void init() throws Exception {
		super.init();
		PdfObjFactory.setInstance(new PdfBoxNativeObjectFactory());
	}

}
