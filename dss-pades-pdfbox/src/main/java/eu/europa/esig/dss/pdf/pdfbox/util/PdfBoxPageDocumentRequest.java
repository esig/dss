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
package eu.europa.esig.dss.pdf.pdfbox.util;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;

import java.util.Objects;

/**
 * Represents a request for operating over a specific page of a given PDF
 * document
 */
public class PdfBoxPageDocumentRequest {

	private DSSDocument pdfDocument;
	private char[] passwordProtection;
	private int page;
	private PdfMemoryUsageSetting pdfMemoryUsageSetting = PdfMemoryUsageSetting.memoryFull();

	/**
	 * @param pdfDocument {@link DSSDocument} to generate screenshot for
	 * @param page        a page number
	 */
	public PdfBoxPageDocumentRequest(DSSDocument pdfDocument, int page) {
		this(pdfDocument, (String) null, page);
	}

	/**
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection {@link String} a PDF password protection phrase
	 * @param page               a page number
	 */
	public PdfBoxPageDocumentRequest(DSSDocument pdfDocument, String passwordProtection, int page) {
		this(pdfDocument, (char[]) (passwordProtection != null ? passwordProtection.toCharArray() : null), page);
	}

	/**
	 * @param pdfDocument        {@link DSSDocument} to generate screenshot for
	 * @param passwordProtection a PDF password protection phrase
	 * @param page               a page number
	 */
	public PdfBoxPageDocumentRequest(DSSDocument pdfDocument, char[] passwordProtection, int page) {
		Objects.requireNonNull(pdfDocument, "pdfDocument shall be defined!");
		this.pdfDocument = pdfDocument;
		this.passwordProtection = passwordProtection;
		this.page = page;
	}

	/**
	 * 
	 * @param pdfMemoryUsageSetting ({@link PdfMemoryUsageSetting} load setting
	 * @return {@link PdfBoxPageDocumentRequest} itself
	 */
	public PdfBoxPageDocumentRequest withPdfMemoryUsageSetting(PdfMemoryUsageSetting pdfMemoryUsageSetting) {
		this.pdfMemoryUsageSetting = pdfMemoryUsageSetting;
		return this;
	}

	public DSSDocument getPdfDocument() {
		return pdfDocument;
	}

	public char[] getPasswordProtection() {
		return passwordProtection;
	}

	public int getPage() {
		return page;
	}

	public PdfMemoryUsageSetting getPdfMemoryUsageSetting() {
		return pdfMemoryUsageSetting;
	}

}
