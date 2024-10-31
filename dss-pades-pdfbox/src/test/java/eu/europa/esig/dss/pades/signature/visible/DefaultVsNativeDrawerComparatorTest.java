/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.signature.visible;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class DefaultVsNativeDrawerComparatorTest extends AbstractTestVisualComparator {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String testName;

	private float similarityLimit;
	
	@BeforeEach
	void init(TestInfo testInfo) {
		testName = testInfo.getTestMethod().get().getName();
		similarityLimit = 0; // use the default one
	}
	
	private void initPdfATest() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());
	}
	
	@Test
	void textTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void textAlphaTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 100));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void textFullyTransparentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 0));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);

		// invisible, expects different test result

		getService().setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");

		getService().setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");

		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
		compareVisualSimilarity(defaultDrawerPdf, nativeDrawerPdf);
		assertTrue(arePdfDocumentsVisuallyEqual(defaultDrawerPdf, nativeDrawerPdf));

		DSSDocument previewNative = getService().previewPageWithVisualSignature(getDocumentToSign(), getSignatureParameters());
		DSSDocument signatureFieldNative = getService().previewSignatureField(getDocumentToSign(), getSignatureParameters());

		assertTrue(areImagesVisuallyEqual(previewNative, PdfBoxUtils.generateScreenshot(getDocumentToSign(), 1)));
		assertFalse(areImagesVisuallyEqual(previewNative, signatureFieldNative));
		assertTrue(areImagesVisuallyEqual(previewNative, PdfBoxUtils.generateScreenshot(nativeDrawerPdf, 1)));
	}
	
	@Test
	void singleImageTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	void singleImagePngTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void singleImagePositionAlignmentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setHeight(200);
		fieldParameters.setWidth(400);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.CENTER);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.TOP);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	private void initVisibleCombinationTest() {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());

		similarityLimit = 0.992f;
	}
	
	@Test
	void combinationTextAndImageTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		
		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void combinationTextAndImageWithZoomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);

		imageParameters.setZoom(50); // reduces 50%
		signatureParameters.setImageParameters(imageParameters);
		
		drawAndCompareVisually();
	}
	
	@Test
	void combinationWithImageOnTopTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void imageAndTextFixedSizeWithDpiTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		imageParameters.setDpi(144);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		fieldParameters.setHeight(100);
		fieldParameters.setWidth(300);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		textParameters.setPadding(20);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void imageAndTextWithDpiTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		imageParameters.setDpi(144);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void imageAndTextWithSignerAndRelativePositioningTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void combinationImageAndTextWithSpecificFieldSize() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(150);
		fieldParameters.setOriginY(150);
		fieldParameters.setWidth(300);
		fieldParameters.setHeight(200);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void smallerImageAndTextOnBottomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(200);
		fieldParameters.setOriginY(300);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.BLUE);
		DSSFileFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf"));
		font.setSize(15);
		textParameters.setFont(font);
		textParameters.setSignerTextPosition(SignerTextPosition.BOTTOM);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void imageAndTextGlobalAlignmentTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
		imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.MIDDLE);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	private SignatureImageParameters createSignatureImageParameters() {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(200);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
		textParameters.setFont(new DSSJavaFont(new Font(Font.SANS_SERIF, Font.BOLD, 10)));
		imageParameters.setTextParameters(textParameters);
		return imageParameters;
	}
	
	@Test
	void multilinesTextAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void multilinesTextWithRightAlignmentAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		imageParameters.getTextParameters().setPadding(50);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void transparentBackgroundTextCenterAndImageBottomTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		similarityLimit = 0.987f;

		Color transparent = new Color(0, 0, 0, 0.25f);
		imageParameters.getTextParameters().setBackgroundColor(transparent);
		imageParameters.getTextParameters().setTextColor(new Color(0.5f, 0.2f, 0.8f, 0.5f));
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		imageParameters.setBackgroundColor(transparent);
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(10);
		fieldParameters.setOriginY(10);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.getTextParameters().setSignerTextVerticalAlignment(SignerTextVerticalAlignment.BOTTOM);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
		
		// margin test
		imageParameters.getTextParameters().setPadding(50);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();

		// center alignment
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();

		// right alignment
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void multilinesWithDpiTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		similarityLimit = 0.990f;

		Color transparent = new Color(0, 0, 0, 0.25f);
		imageParameters.getTextParameters().setBackgroundColor(transparent);
		imageParameters.getTextParameters().setTextColor(new Color(0.5f, 0.2f, 0.8f, 0.5f));
		imageParameters.getTextParameters().setPadding(50);
		imageParameters.setBackgroundColor(transparent);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(150);
		fieldParameters.setOriginY(30);
		imageParameters.setFieldParameters(fieldParameters);
		
		// with dpi
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		imageParameters.setDpi(144);
		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setOriginX(100);
		drawAndCompareVisually();
	}
	
	@Test
	void cyrillicCharactersTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Моя подпись 1");
		textParameters.setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(signatureImageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	void nativeFontTest() throws IOException {
		initVisibleCombinationTest();
		
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nOne more line\nAnd the last line");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		
		textParameters.setFont(new PdfBoxNativeFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA)));
		
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(signatureImageParameters);

		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		Exception exception = assertThrows(UnsupportedOperationException.class , () -> sign(testName + "_default"));
		assertEquals("PdfBoxNativeFont.class can be used only with PdfBoxNativeObjectFactory!", exception.getMessage());
		
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign(testName + "_native");
		assertNotNull(nativeDrawerPdf);
	}
	
	@Test
	void rotationTest() throws IOException {
		initPdfATest();
		similarityLimit = 0.985f;

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nsecond line\nlong line is very long line with long text example this");
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		textParameters.setBackgroundColor(new Color(1, 0, 0, 0.25f));
		textParameters.setTextColor(Color.MAGENTA);
		DSSFileFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansExtraBold.ttf"));
		font.setSize(8);
		textParameters.setFont(font);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setBackgroundColor(new Color(0, 0, 1, 0.25f));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		
		testRotation(VisualSignatureRotation.NONE);
		testRotation(VisualSignatureRotation.AUTOMATIC);
		testRotation(VisualSignatureRotation.ROTATE_90);
		testRotation(VisualSignatureRotation.ROTATE_180);
		testRotation(VisualSignatureRotation.ROTATE_270);
	}
	
	private void testRotation(VisualSignatureRotation visualSignatureRotation) throws IOException {
		signatureParameters.getImageParameters().getFieldParameters().setRotation(visualSignatureRotation);
		compareDoc("/visualSignature/test.pdf");
		compareDoc("/visualSignature/test_90.pdf");
		compareDoc("/visualSignature/test_180.pdf");
		compareDoc("/visualSignature/test_270.pdf");
		compareDoc("/visualSignature/test_-90.pdf");
		compareDoc("/visualSignature/test_-180.pdf");
		compareDoc("/visualSignature/test_-270.pdf");
	}
	
	private void compareDoc(String docPath) throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream(docPath));
		drawAndCompareVisually();
	}
	
	@Test
	void simpleTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	void stretchedTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);
		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.STRETCH);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}

	@Test
	void zoomAndCenterTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);
		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();

		// change directions
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(100);
		drawAndCompareVisually();
	}

	@Test
	void centerTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);
		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.CENTER);
		imageParameters.setBackgroundColor(Color.PINK);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();

		// change directions
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(100);
		drawAndCompareVisually();
	}
	
	@Test
	void rotationOnlyTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(300);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	void zoomAndRotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(300);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setZoom(150);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	void dpiTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		imageParameters.setDpi(300);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(AlertException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("The new signature field position is outside the page dimensions!"));

		fieldParameters.setWidth(400);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();
	}
	
	@Test
	void dpiAndZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));
		imageParameters.setDpi(300);
		imageParameters.setZoom(50);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(20);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	void textExplicitFieldSizeTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(250);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	void textExplicitSizeWithZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(250);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		// TOP not set
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setZoom(50);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	void textWithDpiTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setDpi(144);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	void testWithCMYKImage() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/cmyk.jpg"), "cmyk.jpg", MimeTypeEnum.JPEG));

		signatureParameters.setImageParameters(imageParameters);
		
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
	}

	@Test
	void imageScalingWithTextAndRotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(300);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);

		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		imageParameters.setBackgroundColor(Color.YELLOW);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Signature");
		textParameters.setBackgroundColor(Color.WHITE);
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();

		imageParameters.setImageScaling(ImageScaling.CENTER);
		drawAndCompareVisually();

		// change directions
		fieldParameters.setWidth(300);
		fieldParameters.setHeight(200);
		drawAndCompareVisually();

		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		drawAndCompareVisually();
	}

	@Test
	void imageScalingWithZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);

		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.STRETCH);
		imageParameters.setBackgroundColor(Color.PINK);
		imageParameters.setZoom(50);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();

		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		drawAndCompareVisually();

		imageParameters.setImageScaling(ImageScaling.CENTER);
		drawAndCompareVisually();
	}

	@Test
	void zoomAndCenterAndRotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(300);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		imageParameters.setFieldParameters(fieldParameters);

		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
		imageParameters.setBackgroundColor(Color.PINK);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	void textBasicFittingTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FONT_BASED);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void textAutoFitTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void textAutoFitAndFormatTest() throws IOException {
		initPdfATest();
		similarityLimit = 0.994f;

		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void longWordWithZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by Adolph Blaine Charles David Earl Frederick Gerald Hubert " +
				"Irvin John Kenneth Lloyd Martin Nero Oliver Paul Quincy Randolph Sherman Thomas Uncas Victor William " +
				"Xerxes Yancy Zeus Wolfeschlegelsteinhausenbergerdorffwelchevoralternwarengewissenhaftschaferswessensc" +
				"hafewarenwohlgepflegeundsorgfaltigkeitbeschutzenvorangreifendurchihrraubgierigfeindewelchevoralternzw" +
				"olfhunderttausendjahresvorandieerscheinenvonderersteerdemenschderraumschiffgenachtmittungsteinundsiebe" +
				"niridiumelektrischmotorsgebrauchlichtalsseinursprungvonkraftgestartseinlangefahrthinzwischensternartig" +
				"raumaufdersuchennachbarschaftdersternwelchegehabtbewohnbarplanetenkreisedrehensichundwohinderneuerasse" +
				"vonverstandigmenschlichkeitkonntefortpflanzenundsicherfreuenanlebenslanglichfreudeundruhemitnichteinfur" +
				"chtvorangreifenvorandererintelligentgeschopfsvonhinzwischensternartigraum Sr.");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		imageParameters.setTextParameters(textParameters);
		imageParameters.setZoom(200);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void smallHeightLinebreaksTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(20);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void charactersFillBoxTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(20);
		fieldParameters.setHeight(200);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\nm\nn\np\no\nq\nr\ns\nt\nu\nv\nw\nx\ny\nz");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		textParameters.setPadding(0);
		textParameters.setSignerTextPosition(SignerTextPosition.TOP);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void charactersLinebreakTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(2);
		fieldParameters.setHeight(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("a b c d e f g h i j k l m n p o q r s t u v w x y z");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		textParameters.setPadding(0);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void fillBoxWithImageTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(40);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void fillBoxWithLineBreaksWithImageTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(50);
		imageParameters.setFieldParameters(fieldParameters);
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		textParameters.setPadding(10);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void fillBoxWithBreaksWithImageAndRotationTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(200);
		fieldParameters.setHeight(40);
		fieldParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}

	@Test
	void largeImageFillBoxWithLinebreaksTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(30);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
				"Date: 2021.01.01 01:01:01 WET\n" +
				"Reason: my-reason\n" +
				"Location: my-location");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	void grayscalePdfTest() throws IOException {
		documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/pdfa2a-gray.pdf"));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getOfflineCertificateVerifier());

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.getFieldParameters().setRotation(VisualSignatureRotation.AUTOMATIC);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My Signature");
		textParameters.setTextColor(Color.GRAY);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	void dss2850Test() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(350);
		fieldParameters.setOriginY(750);
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(45);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally sealed by Me");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	void stretchImageWithTextTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		imageParameters.setImageScaling(ImageScaling.STRETCH);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(350);
		fieldParameters.setOriginY(750);
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(45);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally sealed by Me");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		Exception exception = assertThrows(IllegalArgumentException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("ImageScaling 'STRETCH' is not applicable with text wrapping 'FILL_BOX' option!"));

		textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);

		exception = assertThrows(IllegalArgumentException.class, () -> drawAndCompareVisually());
		assertTrue(exception.getMessage().contains("ImageScaling 'STRETCH' is not applicable with text wrapping 'FILL_BOX_AND_LINEBREAK' option!"));

		textParameters.setTextWrapping(TextWrapping.FONT_BASED);

		drawAndCompareVisually();
	}

	@Test
	void centerImageWithFillTextTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG));
		imageParameters.setImageScaling(ImageScaling.CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(250);
		fieldParameters.setOriginY(750);
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(45);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally sealed by Me");
		textParameters.setTextWrapping(TextWrapping.FILL_BOX);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Test
	void zoomAndCenterImageWithFontBaseTextTest() throws IOException {
		initPdfATest();

		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/signature.png")));
		imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(350);
		fieldParameters.setOriginY(750);
		fieldParameters.setWidth(150);
		fieldParameters.setHeight(45);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("Digitally sealed by Me");
		textParameters.setTextWrapping(TextWrapping.FONT_BASED);
		textParameters.setSignerTextPosition(SignerTextPosition.RIGHT);
		imageParameters.setTextParameters(textParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}

	@Override
	protected String getTestName() {
		return testName;
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}
	
	@Override
	public float getSimilarityLimit() {
		if (similarityLimit != 0) {
			return similarityLimit;
		}
		return super.getSimilarityLimit();
	}

}
