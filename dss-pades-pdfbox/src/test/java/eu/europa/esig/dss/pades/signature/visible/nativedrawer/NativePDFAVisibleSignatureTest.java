package eu.europa.esig.dss.pades.signature.visible.nativedrawer;

import eu.europa.esig.dss.pades.signature.visible.AbstractPDFAVisibleSignatureTest;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;

public class NativePDFAVisibleSignatureTest extends AbstractPDFAVisibleSignatureTest {

	@Override
	protected void setCustomFactory() {
		PdfObjFactory.setInstance(new PdfBoxNativeObjectFactory());
	}

}
