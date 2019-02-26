package eu.europa.esig.dss.pdf.pdfbox.visible;

import eu.europa.esig.dss.pades.SignatureImageParameters;

public class PdfBoxNativeSignatureDrawerFactory implements PdfBoxSignatureDrawerFactory {

	@Override
	public PdfBoxSignatureDrawer getSignatureDrawer(SignatureImageParameters imageParameters) {
		return new NativePdfBoxVisibleSignatureDrawer();
	}

}
