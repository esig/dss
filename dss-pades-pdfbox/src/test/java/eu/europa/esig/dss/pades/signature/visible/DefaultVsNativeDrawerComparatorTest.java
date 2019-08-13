package eu.europa.esig.dss.pades.signature.visible;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.junit.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PdfScreenshotUtils;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.pades.SignatureImageParameters.VisualSignatureRotation;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextVerticalAlignment;
import eu.europa.esig.dss.pades.SignatureImageTextParameters.SignerTextPosition;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class DefaultVsNativeDrawerComparatorTest extends PKIFactoryAccess {

	private DocumentSignatureService<PAdESSignatureParameters> service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	/**
	 * The degree of similarity between generated and original images
	 */
	private static final float SIMILARITY_LIMIT = 0.989f;
	
	private void initPdfATest() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
	}
	
	@Test
	public void textTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void textAlphaTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 100));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void textFullyTransparentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 0));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImageTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImagePngTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImagePositionAlignmentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	private void initVisibleCombinationTest() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
	}
	
	@Test
	public void combinationTextAndImageTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		drawAndCompareVisually();
	}
	
	@Test
	public void combinationTextAndImageWithZoomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);

		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		drawAndCompareVisually();
	}
	
	@Test
	public void combinationWithImageOnTopTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void imageAndTextWithDpiTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);
		imageParameters.setDpi(144);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void combinationImageAndTextWithSpecificFieldSize() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(150);
		imageParameters.setyAxis(150);
		imageParameters.setWidth(300);
		imageParameters.setHeight(200);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void smallerImageAndTextOnBottomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		textParameters.setSize(15);
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void imageAndTextGlobalAlignmentTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(100);
		imageParameters.setyAxis(100);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);

		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	private SignatureImageParameters createSignatureImageParameters() {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(200);
		imageParameters.setyAxis(300);
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
		textParameters.setFont(new DSSJavaFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)));
		imageParameters.setTextParameters(textParameters);
		return imageParameters;
	}
	
	@Test
	public void multilinesTextAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void multilinesTextWithRightAlignmentAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		imageParameters.getTextParameters().setPadding(50);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void transparentBackgroundTextCenterAndImageBottomTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		Color transparent = new Color(0, 0, 0, 0.25f);
		imageParameters.getTextParameters().setBackgroundColor(transparent);
		imageParameters.getTextParameters().setTextColor(new Color(0.5f, 0.2f, 0.8f, 0.5f));
		imageParameters.setBackgroundColor(transparent);
		imageParameters.setxAxis(10);
		imageParameters.setyAxis(10);
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignerTextVerticalAlignment.BOTTOM);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
		
		// margin test
		imageParameters.getTextParameters().setPadding(50);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();

		// center alignment
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();

		// right alignment
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		signatureParameters.setSignatureImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void cyrillicCharactersTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Моя подпись 1");
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setSignatureImageParameters(signatureImageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void rotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setSignerTextPosition(SignatureImageTextParameters.SignerTextPosition.RIGHT);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		textParameters.setBackgroundColor(new Color(1, 0, 0, 0.25f));
		textParameters.setTextColor(Color.MAGENTA);
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansExtraBold.ttf")));
		textParameters.setSize(8);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setBackgroundColor(new Color(0, 0, 1, 0.25f));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		signatureParameters.setSignatureImageParameters(imageParameters);
		
		testRotation(VisualSignatureRotation.NONE);
		testRotation(VisualSignatureRotation.AUTOMATIC);
		testRotation(VisualSignatureRotation.ROTATE_90);
		testRotation(VisualSignatureRotation.ROTATE_180);
		testRotation(VisualSignatureRotation.ROTATE_270);
		
	}
	
	private void testRotation(VisualSignatureRotation visualSignatureRotation) throws IOException {
		SignatureImageParameters parameters = signatureParameters.getSignatureImageParameters();
		parameters.setRotation(visualSignatureRotation);
		signatureParameters.setSignatureImageParameters(parameters);
		compareDoc("/visualSignature/test.pdf");
		compareDoc("/visualSignature/test_90.pdf");
		compareDoc("/visualSignature/test_180.pdf");
		compareDoc("/visualSignature/test_270.pdf");
		compareDoc("/visualSignature/test_-90.pdf");
		compareDoc("/visualSignature/test_-180.pdf");
		compareDoc("/visualSignature/test_-270.pdf");
	}
	
	@Test
	public void simpleTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		
		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void stretchedTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(20);
		imageParameters.setWidth(100);
		imageParameters.setHeight(150);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void rotationOnlyTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void zoomAndRotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(50);
		imageParameters.setWidth(100);
		imageParameters.setHeight(300);
		
		imageParameters.setZoom(150);
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void dpiTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(20);
		imageParameters.setDpi(300);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void dpiAndZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setxAxis(20);
		imageParameters.setyAxis(20);
		imageParameters.setDpi(300);
		imageParameters.setZoom(50);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void testExplicitFieldSizeTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setxAxis(50);
		imageParameters.setyAxis(50);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setWidth(250);
		imageParameters.setHeight(100);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	public void textExplicitSizeWithZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setxAxis(50);
		imageParameters.setyAxis(50);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setWidth(250);
		imageParameters.setHeight(100);
		imageParameters.setZoom(200);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	public void textWithDpiTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setxAxis(50);
		imageParameters.setyAxis(50);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setDpi(144);

		signatureParameters.setSignatureImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	private void compareDoc(String docPath) throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream(docPath));
		drawAndCompareVisually();
	}
	
	private void drawAndCompareVisually() throws IOException {
		PdfObjFactory.setInstance(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");
		PdfObjFactory.setInstance(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
	}
	
	private void drawAndCompareExplicitly() throws IOException {
		PdfObjFactory.setInstance(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");
		PdfObjFactory.setInstance(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		assertTrue(PdfScreenshotUtils.areVisuallyEqual(defaultDrawerPdf, nativeDrawerPdf));
	}
	
	private DSSDocument sign(String docName) throws IOException {
		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument document = service.signDocument(documentToSign, signatureParameters, signatureValue);
		// document.save("target/" + docName + ".pdf");
		return document;
	}
	
	private void compareAnnotations(DSSDocument doc1, DSSDocument doc2) throws IOException {
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
					// assert max 0.5 pixels difference, due to the fact that the default implementation 
					// does not support precise datatypes (double/float)
					assertEquals(rect1.getLowerLeftX(), rect2.getLowerLeftX(), 0.5);
					assertEquals(rect1.getLowerLeftY(), rect2.getLowerLeftY(), 0.5);
					assertEquals(rect1.getUpperRightX(), rect2.getUpperRightX(), 0.5);
					assertEquals(rect1.getUpperRightY(), rect2.getUpperRightY(), 0.5);
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
