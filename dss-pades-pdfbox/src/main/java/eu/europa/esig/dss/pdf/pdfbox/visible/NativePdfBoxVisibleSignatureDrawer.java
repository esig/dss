package eu.europa.esig.dss.pdf.pdfbox.visible;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDTrueTypeFont;
import org.apache.pdfbox.pdmodel.font.encoding.WinAnsiEncoding;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.utils.Utils;

public class NativePdfBoxVisibleSignatureDrawer extends AbstractPdfBoxSignatureDrawer {
	
	private PDFont pdFont;
	
	@Override
	public void init(SignatureImageParameters parameters, PDDocument document, SignatureOptions signatureOptions) throws IOException {
		super.init(parameters, document, signatureOptions);
		if (parameters.getTextParameters() != null) {
			this.pdFont = initFont();
		}
	}
	
	private PDFont initFont() throws IOException {
		try (InputStream is = parameters.getTextParameters().getFont().openStream()) {
			return PDTrueTypeFont.load(document, is, WinAnsiEncoding.INSTANCE);
		}
	}
	
	@Override
	public void draw() throws IOException {
		ByteArrayInputStream bais = null;
		try (PDDocument doc = new PDDocument())
        {
			PDPage page = new PDPage(document.getPage(parameters.getPage() - 1).getMediaBox());
			SignatureFieldDimensionAndPositionBuilder dimensionAndPositionBuilder = new SignatureFieldDimensionAndPositionBuilder(parameters, page);
			SignatureFieldDimensionAndPosition dimensionAndPosition = dimensionAndPositionBuilder.build();
			doc.addPage(page);
			PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

            PDRectangle rectangle = getPdRectangle(dimensionAndPosition, page);
            widget.setRectangle(rectangle);
            
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            
            form.setBBox(new PDRectangle(rectangle.getWidth(), rectangle.getHeight()));
            
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);
            
            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream);)
            {
            	if (parameters.getBackgroundColor() != null) {
                    cs.setNonStrokingColor(parameters.getBackgroundColor());
                    // fill a whole box with the background color
                    cs.addRect(-5000, -5000, 10000, 10000);
                    cs.fill();
            	}
            	if (parameters.getImage() != null) {
                    cs.saveGraphicsState();
                    cs.transform(Matrix.getScaleInstance(dimensionAndPosition.getxDpiRatio(), dimensionAndPosition.getyDpiRatio()));
            		InputStream image = parameters.getImage().openStream();
            		byte[] bytes = IOUtils.toByteArray(image);
            		PDImageXObject imageXObject = PDImageXObject.createFromByteArray(doc, bytes, parameters.getImage().getName());
                	cs.drawImage(imageXObject, dimensionAndPosition.getImageX(), dimensionAndPosition.getImageY());
                    cs.restoreGraphicsState();
            	}
            	SignatureImageTextParameters textParameters = parameters.getTextParameters();
            	if (textParameters != null && Utils.isStringNotEmpty(textParameters.getText())) {
                    float fontSize = textParameters.getSize();
                    cs.beginText();
                    cs.setFont(pdFont, fontSize);
                    cs.setNonStrokingColor(textParameters.getTextColor());
                    cs.newLineAtOffset(dimensionAndPosition.getTextX(), 
                    		// align vertical position
                    		dimensionAndPosition.getTextY() + dimensionAndPosition.getTextHeight() - fontSize);
                    String[] strings = textParameters.getText().split(System.lineSeparator());
                    for (String str : strings) {
                        cs.showText(str);
                        cs.newLine();
                    }
                    cs.endText();
            	}
            }
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            bais = new ByteArrayInputStream(baos.toByteArray());
            
        }
		signatureOptions.setVisualSignature(bais);
		bais.close();
		signatureOptions.setPage(parameters.getPage() - 1);
	}
	
	private PDRectangle getPdRectangle(SignatureFieldDimensionAndPosition dimensionAndPosition, PDPage page) {
		PDRectangle pageRect = page.getMediaBox();
		PDRectangle pdRectangle = new PDRectangle();
		
		pdRectangle.setLowerLeftX(dimensionAndPosition.getBoxX());
		pdRectangle.setLowerLeftY(pageRect.getHeight() - dimensionAndPosition.getBoxY() - dimensionAndPosition.getBoxHeight()); // because PDF starts to count from bottom
		pdRectangle.setUpperRightX(dimensionAndPosition.getBoxX() + dimensionAndPosition.getBoxWidth());
		pdRectangle.setUpperRightY(pageRect.getHeight() - dimensionAndPosition.getBoxY());
		return pdRectangle;
	}

}
