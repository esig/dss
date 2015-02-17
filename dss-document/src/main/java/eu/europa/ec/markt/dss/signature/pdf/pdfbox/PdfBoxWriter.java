/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.pdmodel.PDDocument;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.signature.pdf.PdfWriter;

class PdfBoxWriter implements PdfWriter {

	PDDocument document;

	private OutputStream output;

	private FileInputStream tempInput;

	private FileOutputStream tempOutput;

	private File tempDocumentOut;

	public PdfBoxWriter(PDDocument document, OutputStream output)
			throws IOException {

		this.document = document;
		try {
			this.output = output;

			File tempDocumentIn = new File("target/copyoffile.pdf");
			tempOutput = new FileOutputStream(tempDocumentIn);
			document.save(tempOutput);
			tempOutput.close();

			tempInput = new FileInputStream(tempDocumentIn);
			tempDocumentOut = new File("target/copyoffileout.pdf");
			tempOutput = new FileOutputStream(tempDocumentOut);
            DSSUtils.copy(tempInput, tempOutput);
			tempInput.close();

			tempInput = new FileInputStream(tempDocumentIn);

		} catch (COSVisitorException e) {
			throw new IOException(e);
		}

	}

	@Override
	public void saveIncremental() throws IOException {
		try {
            document.saveIncremental(tempInput, tempOutput);
			tempOutput.close();
			tempInput.close();

			tempInput = new FileInputStream(tempDocumentOut);
            DSSUtils.copy(tempInput, output);
			tempInput.close();
		} catch (COSVisitorException e) {
			throw new IOException(e);
		}
	}

}
