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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.pades.PAdESCommonParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfValidationDataContainer;
import eu.europa.esig.dss.pdf.modifications.PdfDifferencesFinder;
import eu.europa.esig.dss.pdf.modifications.PdfObjectModificationsFinder;
import eu.europa.esig.dss.signature.resources.DSSResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import java.util.List;

/**
 * The usage of this interface permits the user to choose the underlying PDF library used to create PDF signatures.
 *
 */
public interface PDFSignatureService {

	/**
	 * Returns the message-digest computed on PDF signature revision's ByteRange
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return {@link DSSMessageDigest}
	 */
	DSSMessageDigest messageDigest(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Signs a PDF document
	 *
	 * @param toSignDocument
	 *            the pdf document to be signed
	 * @param cmsSignedData
	 *            the encoded CMS Signed data
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return {@link DSSDocument}
	 */
	DSSDocument sign(final DSSDocument toSignDocument, final byte[] cmsSignedData,
					 final PAdESCommonParameters parameters);

	/**
	 * Retrieves revisions from a PDF document
	 *
	 * @param document
	 *            the document to extract revisions from
	 * @param pwd
	 *            the password protection phrase used to encrypt the PDF document
	 *            use 'null' value for not an encrypted document
	 * @return list of extracted {@link PdfRevision}s
	 */
	List<PdfRevision> getRevisions(final DSSDocument document, final char[] pwd);

	/**
	 * This method adds the DSS dictionary (Baseline-LT) to a document without password-protection and without VRI dictionary.
	 * 
	 * @param document
	 *            the document to be extended
	 * @param validationDataForInclusion
	 *            {@link PdfValidationDataContainer}
	 * @return the pdf document with the added dss dictionary
	 */
	DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion);

	/**
	 * This method adds the DSS dictionary (Baseline-LT) to a password-protected document without inclusion of VRI dictionary.
	 *
	 * @param document
	 *            the document to be extended
	 * @param validationDataForInclusion
	 *            {@link PdfValidationDataContainer}
	 * @param pwd
	 *            the password protection used to create the encrypted document (optional)
	 * @return the pdf document with the added dss dictionary
	 */
	DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion,
								 final char[] pwd);

	/**
	 * This method adds the DSS dictionary (Baseline-LT) to a password-protected document with a VRI dictionary if defined.
	 *
	 * @param document
	 *            the document to be extended
	 * @param validationDataForInclusion
	 *            {@link PdfValidationDataContainer}
	 * @param pwd
	 *            the password protection used to create the encrypted document (optional)
	 * @param includeVRIDict
	 *            defines whether VRI dictionary should be included to the created DSS dictionary
	 * @return the pdf document with the added dss dictionary
	 */
	DSSDocument addDssDictionary(final DSSDocument document, final PdfValidationDataContainer validationDataForInclusion,
								 final char[] pwd, final boolean includeVRIDict);

	/**
	 * This method returns not signed signature-fields
	 * 
	 * @param document
	 *            the pdf document
	 * @return the list of empty signature fields
	 */
	List<String> getAvailableSignatureFields(final DSSDocument document);

	/**
	 * Returns not-signed signature fields from an encrypted document
	 *
	 * @param document
	 *            the pdf document
	 * @param pwd
	 *            the password protection phrase used to encrypt the document
	 * @return the list of not signed signature field names
	 */
	List<String> getAvailableSignatureFields(final DSSDocument document, final char[] pwd);

	/**
	 * This method allows to add a new signature field to an existing pdf document
	 * 
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @return the pdf document with the new added signature field
	 */
	DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters);

	/**
	 * This method allows to add a new signature field to an existing encrypted pdf document
	 *
	 * @param document
	 *            the pdf document
	 * @param parameters
	 *            the parameters with the coordinates,... of the signature field
	 * @param pwd
	 *            the password protection used to create the encrypted document (optional)
	 * @return the pdf document with the new added signature field
	 */
	DSSDocument addNewSignatureField(final DSSDocument document, final SignatureFieldParameters parameters,
									 final char[] pwd);

	/**
	 * Analyze the PDF revision and try to detect any modification (shadow attacks) for signatures
	 *
	 * @param document    {@link DSSDocument} the document
	 * @param signatures  the different signatures to be analysed
	 * @param pwd         {@link String} password protection
	 */
	void analyzePdfModifications(final DSSDocument document, final List<AdvancedSignature> signatures, final char[] pwd);

	/**
	 * Analyze the PDF revision and try to detect any modification (shadow attacks) for PDf document timestamps
	 *
	 * @param document    {@link DSSDocument} the document
	 * @param timestamps  the detached document timestamps to be analysed
	 * @param pwd         {@link String} password protection
	 */
	void analyzeTimestampPdfModifications(final DSSDocument document, final List<TimestampToken> timestamps, final char[] pwd);

	/**
	 * Returns a page preview with the visual signature
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return a DSSDocument with the PNG picture
	 */
	DSSDocument previewPageWithVisualSignature(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Returns a preview of the signature field
	 *
	 * @param toSignDocument
	 *            the document to be signed
	 * @param parameters
	 *            the signature/timestamp parameters
	 * @return a DSSDocument with the PNG picture
	 */
	DSSDocument previewSignatureField(final DSSDocument toSignDocument, final PAdESCommonParameters parameters);

	/**
	 * Sets {@code DSSResourcesFactoryBuilder} to be used for a {@code DSSResourcesHandler}
	 * creation in internal methods. {@code DSSResourcesHandler} defines a way to operate with OutputStreams and
	 * create {@code DSSDocument}s.
	 *
	 * Default : {@code eu.europa.esig.dss.signature.resources.InMemoryResourcesHandler}. Works with data in memory.
	 *
	 * @param resourcesHandlerBuilder {@link DSSResourcesHandlerBuilder}
	 */
	void setResourcesHandlerBuilder(DSSResourcesHandlerBuilder resourcesHandlerBuilder);

	/**
	 * Sets the {@code PdfDifferencesFinder} used to find the differences on pages between given PDF revisions.
	 *
	 * Default : {@code eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder}
	 *
	 * @param pdfDifferencesFinder {@link PdfDifferencesFinder}
	 */
	void setPdfDifferencesFinder(PdfDifferencesFinder pdfDifferencesFinder);

	/**
	 * Sets the {@code PdfObjectModificationsFinder} used to find the differences between internal PDF objects occurred
	 * between given PDF revisions.
	 *
	 * Default : {@code eu.europa.esig.dss.pdf.modifications.DefaultPdfObjectModificationsFinder}
	 *
	 * @param pdfObjectModificationsFinder {@link PdfObjectModificationsFinder}
	 */
	void setPdfObjectModificationsFinder(PdfObjectModificationsFinder pdfObjectModificationsFinder);

	/**
	 * Sets the {@code PdfPermissionsChecker} used to verify the PDF document rules for a new signature creation
	 *
	 * @param pdfPermissionsChecker {@link PdfPermissionsChecker}
	 */
	void setPdfPermissionsChecker(PdfPermissionsChecker pdfPermissionsChecker);

	/**
	 * Sets the {@code PdfSignatureFieldPositionChecker} used to verify the validity of new signature field placement.
	 * For example to ensure the new signature field lies within PDF page borders and/or
	 * it does not overlap with existing signature fields.
	 *
	 * @param pdfSignatureFieldPositionChecker {@link PdfPermissionsChecker}
	 */
	void setPdfSignatureFieldPositionChecker(PdfSignatureFieldPositionChecker pdfSignatureFieldPositionChecker);

}
