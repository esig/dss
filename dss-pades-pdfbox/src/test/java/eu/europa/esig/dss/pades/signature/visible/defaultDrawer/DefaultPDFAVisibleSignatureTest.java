package eu.europa.esig.dss.pades.signature.visible.defaultDrawer;

import eu.europa.esig.dss.pades.signature.visible.AbstractPDFAVisibleSignatureTest;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;

public class DefaultPDFAVisibleSignatureTest extends AbstractPDFAVisibleSignatureTest {

	@Override
	protected void setCustomFactory() {
		PdfObjFactory.setInstance(new PdfBoxDefaultObjectFactory());
	}

}
