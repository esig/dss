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
package eu.europa.esig.dss.pdf.pdfbox.visible;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import eu.europa.esig.dss.pdf.visible.ImageAndResolution;
import eu.europa.esig.dss.pdf.visible.ImageUtils;

public class DefaultPdfBoxVisibleSignatureDrawer extends AbstractPdfBoxSignatureDrawer {

	@Override
	public void draw() throws IOException {

		// DSS-747. Using the DPI resolution to convert java size to dot
		ImageAndResolution ires = ImageUtils.create(parameters);

		SignatureImageAndPosition signatureImageAndPosition = SignatureImageAndPositionProcessor.process(parameters, document, ires);

		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(document, new ByteArrayInputStream(signatureImageAndPosition.getSignatureImage()),
				parameters.getPage());

		visibleSig.xAxis(signatureImageAndPosition.getX());
		visibleSig.yAxis(signatureImageAndPosition.getY());

		if ((parameters.getWidth() != 0) && (parameters.getHeight() != 0)) {
			visibleSig.width(parameters.getWidth());
			visibleSig.height(parameters.getHeight());
		} else {
			visibleSig.width(ires.toXPoint(visibleSig.getWidth()));
			visibleSig.height(ires.toYPoint(visibleSig.getHeight()));
		}
		visibleSig.zoom(((float) parameters.getZoom()) - 100); // pdfbox is 0 based

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

		signatureOptions.setVisualSignature(signatureProperties);
		signatureOptions.setPage(parameters.getPage() - 1); // DSS-1138
	}


}
