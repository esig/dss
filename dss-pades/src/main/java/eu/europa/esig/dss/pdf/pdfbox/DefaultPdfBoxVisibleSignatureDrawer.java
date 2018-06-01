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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.visible.ImageAndResolution;
import eu.europa.esig.dss.pades.signature.visible.ImageUtils;

public class DefaultPdfBoxVisibleSignatureDrawer implements PdfBoxVisibleSignatureDrawer {

	@Override
	public SignatureOptions createVisualSignature(final PDDocument doc, final SignatureImageParameters params)
			throws IOException {
		SignatureOptions sigOptions = new SignatureOptions();

		if (params != null) {
			// DSS-747. Using the DPI resolution to convert java size to dot
			ImageAndResolution ires = ImageUtils.create(params);

			SignatureImageAndPosition signatureImageAndPosition = SignatureImageAndPositionProcessor.process(params,
					doc, ires);

			PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(doc,
					new ByteArrayInputStream(signatureImageAndPosition.getSignatureImage()), params.getPage());

			visibleSig.xAxis(signatureImageAndPosition.getX());
			visibleSig.yAxis(signatureImageAndPosition.getY());

			if ((params.getWidth() != 0) && (params.getHeight() != 0)) {
				visibleSig.width(params.getWidth());
				visibleSig.height(params.getHeight());
			} else {
				visibleSig.width(ires.toXPoint(visibleSig.getWidth()));
				visibleSig.height(ires.toYPoint(visibleSig.getHeight()));
			}
			visibleSig.zoom(params.getZoom() - 100); // pdfbox is 0 based

			PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
			signatureProperties.visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

			sigOptions.setVisualSignature(signatureProperties);
			sigOptions.setPage(params.getPage() - 1); // DSS-1138
		}

		return sigOptions;
	}

}
