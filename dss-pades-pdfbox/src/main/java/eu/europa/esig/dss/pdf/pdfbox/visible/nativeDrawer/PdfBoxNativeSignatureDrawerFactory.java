package eu.europa.esig.dss.pdf.pdfbox.visible.nativeDrawer;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;

public class PdfBoxNativeSignatureDrawerFactory implements PdfBoxSignatureDrawerFactory {

	@Override
	public PdfBoxSignatureDrawer getSignatureDrawer(SignatureImageParameters imageParameters) {
		return new NativePdfBoxVisibleSignatureDrawer();
	}

}
