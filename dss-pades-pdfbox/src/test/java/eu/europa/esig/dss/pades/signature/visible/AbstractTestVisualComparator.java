package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PdfScreenshotUtils;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.test.PKIFactoryAccess;

public abstract class AbstractTestVisualComparator extends PKIFactoryAccess {
	
	/**
	 * The degree of similarity between generated and original images
	 */
	private static final float SIMILARITY_LIMIT = 0.987f;
	
	protected abstract String getTestName();
	protected abstract PAdESService getService();
	protected abstract DSSDocument getDocumentToSign();
	protected abstract PAdESSignatureParameters getSignatureParameters();
	
	protected void drawAndCompareVisually() throws IOException {
		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign(getTestName() + "_default");
		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign(getTestName() + "_native");
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
	}
	
	protected void drawAndCompareExplicitly() throws IOException {
		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");
		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		assertTrue(PdfScreenshotUtils.areVisuallyEqual(defaultDrawerPdf, nativeDrawerPdf));
	}
	
	protected DSSDocument sign(String docName) throws IOException {
		ToBeSigned dataToSign = getService().getDataToSign(getDocumentToSign(), getSignatureParameters());
		SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument document = getService().signDocument(getDocumentToSign(), getSignatureParameters(), signatureValue);
		// document.save("target/" + docName + ".pdf");
		return document;
	}
	
	protected void compareAnnotations(DSSDocument doc1, DSSDocument doc2) throws IOException {
		try (InputStream is1 = doc1.openStream(); InputStream is2 = doc2.openStream(); 
				PDDocument pdDoc1 = PDDocument.load(is1); PDDocument pdDoc2 = PDDocument.load(is2);) {
			assertEquals(pdDoc1.getNumberOfPages(), pdDoc2.getNumberOfPages());
			for (int i = 0; i < pdDoc1.getNumberOfPages(); i++) {
				PDPage page1 = pdDoc1.getPage(i);
				PDPage page2 = pdDoc2.getPage(i);
				assertEquals(page1.getRotation(), page2.getRotation());
				assertEquals(page1.getAnnotations().size(), page2.getAnnotations().size());
				for (int j = 0; j < page1.getAnnotations().size(); j++) {
					PDRectangle rect1 = page1.getAnnotations().get(j).getRectangle();
					PDRectangle rect2 = page2.getAnnotations().get(j).getRectangle();
					// assert max 2% difference, due to different text size computation
					// NOTE: must be non-negative
					assertEquals(rect1.getLowerLeftX(), rect2.getLowerLeftX(), Math.abs(rect1.getLowerLeftX()) / 50);
					assertEquals(rect1.getLowerLeftY(), rect2.getLowerLeftY(), Math.abs(rect1.getLowerLeftY()) / 50);
					assertEquals(rect1.getUpperRightX(), rect2.getUpperRightX(), Math.abs(rect1.getUpperRightX()) / 50);
					assertEquals(rect1.getUpperRightY(), rect2.getUpperRightY(), Math.abs(rect1.getUpperRightY()) / 50);
				}
			}
		}
	}
	
	private void compareVisualSimilarity(DSSDocument doc1, DSSDocument doc2) throws IOException {
		try (InputStream is1 = doc1.openStream(); InputStream is2 = doc2.openStream();
				PDDocument pdDoc1 = PDDocument.load(is1); PDDocument pdDoc2 = PDDocument.load(is2);) {
			PdfScreenshotUtils.checkPdfSimilarity(pdDoc1, pdDoc2, SIMILARITY_LIMIT);
		}
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
