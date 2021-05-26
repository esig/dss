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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.enumerations.SignerTextPosition;
import eu.europa.esig.dss.enumerations.SignerTextVerticalAlignment;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.DSSJavaFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxDefaultObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxNativeFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Tag("slow")
public class DefaultVsNativeDrawerComparatorTest extends AbstractTestVisualComparator {

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;
	
	private String testName;

	private float similarityLimit;
	
	@BeforeEach
	public void init(TestInfo testInfo) {
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
	public void textTest() throws IOException {
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
	public void textAlphaTest() throws IOException {
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
	public void textFullyTransparentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(new Color(0, 255, 0, 0));
		imageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImageTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImagePngTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareExplicitly();
	}
	
	@Test
	public void singleImagePositionAlignmentTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
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
	public void combinationTextAndImageTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(100);
		fieldParameters.setOriginY(100);
		imageParameters.setFieldParameters(fieldParameters);

		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature");
		textParameters.setTextColor(Color.GREEN);
		imageParameters.setTextParameters(textParameters);
		
		signatureParameters.setImageParameters(imageParameters);
		
		drawAndCompareVisually();
	}
	
	@Test
	public void combinationTextAndImageWithZoomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		
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
	public void combinationWithImageOnTopTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));

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
		drawAndCompareVisually();
	}
	
	@Test
	public void imageAndTextFixedSizeWithDpiTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
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
	public void imageAndTextWithDpiTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
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
		drawAndCompareVisually();
	}
	
	@Test
	public void imageAndTextWithSignerAndRelativePositioningTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		
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
		drawAndCompareVisually();
	}
	
	@Test
	public void combinationImageAndTextWithSpecificFieldSize() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

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
	public void smallerImageAndTextOnBottomTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		
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
	public void imageAndTextGlobalAlignmentTest() throws IOException {
		initVisibleCombinationTest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

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
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(200);
		fieldParameters.setOriginY(300);
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
	public void multilinesTextAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void multilinesTextWithRightAlignmentAndImageTest() throws IOException {
		SignatureImageParameters imageParameters = createSignatureImageParameters();
		imageParameters.getTextParameters().setFont(new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansBold.ttf")));
		imageParameters.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
		imageParameters.getTextParameters().setPadding(50);
		signatureParameters.setImageParameters(imageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void transparentBackgroundTextCenterAndImageBottomTest() throws IOException {
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
	public void multilinesWithDpiTest() throws IOException {
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
		signatureParameters.setImageParameters(signatureImageParameters);
		drawAndCompareVisually();
	}
	
	@Test
	public void nativeFontTest() throws IOException {
		initVisibleCombinationTest();
		
		SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
		
		SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
		textParameters.setText("My signature\nOne more line\nAnd the last line");
		textParameters.setTextColor(Color.BLUE);
		textParameters.setBackgroundColor(Color.YELLOW);
		textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.CENTER);
		
		textParameters.setFont(new PdfBoxNativeFont(PDType1Font.HELVETICA));
		
		signatureImageParameters.setTextParameters(textParameters);
		signatureParameters.setImageParameters(signatureImageParameters);

		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		Exception exception = assertThrows(DSSException.class , () -> sign(testName + "_default"));
		assertEquals("PdfBoxNativeFont.class can be used only with PdfBoxNativeObjectFactory!", exception.getMessage());
		
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign(testName + "_native");
		assertNotNull(nativeDrawerPdf);
	}
	
	@Test
	public void rotationTest() throws IOException {
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
		SignatureImageParameters parameters = signatureParameters.getImageParameters();
		parameters.setRotation(visualSignatureRotation);
		signatureParameters.setImageParameters(parameters);
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
	public void simpleTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void stretchedTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));
		
		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(150);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void rotationOnlyTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(300);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void zoomAndRotationTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG));

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		fieldParameters.setWidth(100);
		fieldParameters.setHeight(300);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setZoom(150);
		imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);
		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void dpiTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setDpi(300);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareExplicitly();
	}
	
	@Test
	public void dpiAndZoomTest() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG));
		imageParameters.setDpi(300);
		imageParameters.setZoom(50);

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(20);
		fieldParameters.setOriginY(20);
		imageParameters.setFieldParameters(fieldParameters);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	public void textExplicitFieldSizeTest() throws IOException {
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
	public void textExplicitSizeWithZoomTest() throws IOException {
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
		imageParameters.setTextParameters(textParameters);
		
		imageParameters.setZoom(50);

		signatureParameters.setImageParameters(imageParameters);

		drawAndCompareVisually();
	}
	
	@Test
	public void textWithDpiTest() throws IOException {
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
	public void testWithCMYKImage() throws IOException {
		initPdfATest();
		SignatureImageParameters imageParameters = new SignatureImageParameters();

		SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
		fieldParameters.setOriginX(50);
		fieldParameters.setOriginY(50);
		imageParameters.setFieldParameters(fieldParameters);
		
		imageParameters.setImage(new InMemoryDocument(getClass().getResourceAsStream("/cmyk.jpg"), "cmyk.jpg", MimeType.JPEG));

		signatureParameters.setImageParameters(imageParameters);
		
		service.setPdfObjFactory(new PdfBoxDefaultObjectFactory());
		DSSDocument defaultDrawerPdf = sign("default");
		service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
		DSSDocument nativeDrawerPdf = sign("native");
		compareAnnotations(defaultDrawerPdf, nativeDrawerPdf);
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
