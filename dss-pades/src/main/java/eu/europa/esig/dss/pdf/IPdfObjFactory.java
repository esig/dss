/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.spi.signature.resources.DSSResourcesHandlerBuilder;

/**
 * Loads the relevant implementation of {@code PDFSignatureService}
 */
public interface IPdfObjFactory {

	/**
	 * The services used for a content timestamp creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	PDFSignatureService newContentTimestampService();

	/**
	 * The services used for a signature creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	PDFSignatureService newPAdESSignatureService();

	/**
	 * The services used for a signature timestamp creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	PDFSignatureService newSignatureTimestampService();

	/**
	 * The services used for an archive timestamp creation
	 *
	 * @return {@link PDFSignatureService}
	 */
	PDFSignatureService newArchiveTimestampService();

	/**
	 * This method sets a {@code DSSResourcesHandlerBuilder} to be used for operating with internal objects
	 * during the signature creation procedure.
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder);

	/**
	 * This method is used to set a custom {@code PdfDifferencesFinder} to detect differences
	 * between signed and final PDF document revisions.
	 *
	 * @param pdfDifferencesFinder {@link PdfDifferencesFinder}
	 */
	void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder);

	/**
	 * This method is used to set a custom {@code PdfObjectModificationsFinder} to detect modifications occurred
	 * within internal PDF objects between signed and final PDF document revisions.
	 *
	 * @param pdfObjectModificationsFinder {@link PdfObjectModificationsFinder}
	 */
	void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder);

	/**
	 * This method is used to set a custom {@code PdfPermissionsChecker} to verify the PDF document
	 * encryption dictionary permission rules for a new signature creation, when applicable
	 *
	 * @param pdfPermissionsChecker {@link PdfPermissionsChecker}
	 */
	void setPdfPermissionsChecker(PdfPermissionsChecker pdfPermissionsChecker);

	/**
	 * This method is used to set a custom {@code PdfSignatureFieldPositionChecker} to verify the validity
	 * of new signature field placement.
	 *
	 * @param pdfSignatureFieldPositionChecker {@link PdfPermissionsChecker}
	 */
	void setPdfSignatureFieldPositionChecker(PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker);
	
	/**
	 * This method is used to set a custom {@code PdfMemoryUsageSetting} to specify the load mode of the PDF document 
	 * 
	 * @param pdfMemoryUsageSetting {@link PdfMemoryUsageSetting}
	 */
	void setPdfMemoryUsageSetting(PdfMemoryUsageSetting pdfMemoryUsageSetting);

}
