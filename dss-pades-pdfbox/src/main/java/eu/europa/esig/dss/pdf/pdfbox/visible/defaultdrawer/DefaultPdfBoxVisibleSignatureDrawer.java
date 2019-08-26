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
package eu.europa.esig.dss.pdf.pdfbox.visible.defaultdrawer;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.pdfbox.visible.AbstractPdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.ImageRotationUtils;
import eu.europa.esig.dss.pdf.visible.CommonDrawerUtils;
import eu.europa.esig.dss.pdf.visible.ImageAndResolution;

public class DefaultPdfBoxVisibleSignatureDrawer extends AbstractPdfBoxSignatureDrawer {

	@Override
	public void draw() throws IOException {
		// DSS-747. Using the DPI resolution to convert java size to dot
		ImageAndResolution ires = DefaultDrawerImageUtils.create(parameters);

		SignatureImageAndPosition signatureImageAndPosition = SignatureImageAndPositionProcessor.process(parameters, document, ires);

		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(document, new ByteArrayInputStream(signatureImageAndPosition.getSignatureImage()),
				parameters.getPage());

		visibleSig.xAxis(signatureImageAndPosition.getX());
		visibleSig.yAxis(signatureImageAndPosition.getY());
		
		float width = parameters.getWidth();
		float height = parameters.getHeight();
		if (ImageRotationUtils.isSwapOfDimensionsRequired(parameters.getRotation())) {
			width = parameters.getHeight();
			height = parameters.getWidth();
		}
		
		if (width != 0) {
			visibleSig.width(width);
		} else if (parameters.getTextParameters() != null) {
			visibleSig.width(CommonDrawerUtils.toDpiAxisPoint((float)visibleSig.getWidth(), CommonDrawerUtils.getDpi(parameters.getDpi())));
		} else {
			visibleSig.width(ires.toXPoint(visibleSig.getWidth()));
		}
		if (height != 0) {
			visibleSig.height(height);
		} else if (parameters.getTextParameters() != null) {
			visibleSig.height(CommonDrawerUtils.toDpiAxisPoint((float)visibleSig.getHeight(), CommonDrawerUtils.getDpi(parameters.getDpi())));
		} else {
			visibleSig.height(ires.toYPoint(visibleSig.getHeight()));
		}

		// zoom image only when it does not have text parameters, in other case does zoom inside DefaultDrawerImageUtils.create() method
		if (parameters.getImage() == null || parameters.getTextParameters() == null) {
			visibleSig.zoom(((float) parameters.getZoom()) - 100); // pdfbox is 0 based
		}
		
		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true);
		signatureProperties.setPdVisibleSignature(visibleSig);
		signatureProperties.buildSignature();
		
		signatureOptions.setVisualSignature(signatureProperties);
		signatureOptions.setPage(parameters.getPage() - 1); // DSS-1138
	}

	@Override
	protected String getColorSpaceName(DSSDocument image) throws IOException {
		return COSName.DEVICERGB.getName();
	}

}
