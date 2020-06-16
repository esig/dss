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
package eu.europa.esig.dss.pdf.openpdf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lowagie.text.exceptions.BadPasswordException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.AcroFields.Item;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfReader;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.InvalidPasswordException;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSigDictWrapper;
import eu.europa.esig.dss.pdf.SingleDssDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public class ITextDocumentReader implements PdfDocumentReader {

	private static final Logger LOG = LoggerFactory.getLogger(ITextDocumentReader.class);
	
	private final PdfReader pdfReader;
	
	private Map<PdfSignatureDictionary, List<String>> signatureDictionaryMap;

	/**
	 * Default constructor of the OpenPDF implementation of the Reader
	 * 
	 * @param dssDocument {@link DSSDocument} to read
	 * @throws IOException if an exception occurs
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(DSSDocument dssDocument) throws IOException, InvalidPasswordException {
		this(dssDocument, null);
	}

	/**
	 * The OpenPDF implementation of the Reader
	 * 
	 * @param dssDocument {@link DSSDocument} to read
	 * @param passwordProtection binaries of a password to open a protected document
	 * @throws IOException if an exception occurs
	 * @throws InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(DSSDocument dssDocument, byte[] passwordProtection) throws IOException, InvalidPasswordException {
		Objects.requireNonNull(dssDocument, "The document must be defined!");
		try (InputStream is = dssDocument.openStream()) {
			this.pdfReader = new PdfReader(is, passwordProtection);
		} catch (BadPasswordException e) {
            throw new InvalidPasswordException(e.getMessage());
		}
	}

	/**
	 * The OpenPDF implementation of the Reader
	 * 
	 * @param binaries a byte array of a PDF to read
	 * @param passwordProtection binaries of a password to open a protected document
	 * @throws IOException if an exception occurs
	 * @throws eu.europa.esig.dss.pades.InvalidPasswordException if the password is not provided or invalid for a protected document
	 */
	public ITextDocumentReader(byte[] binaries, byte[] passwordProtection) throws IOException, InvalidPasswordException {
		Objects.requireNonNull(binaries, "The document binaries must be defined!");
		try {
			this.pdfReader = new PdfReader(binaries, passwordProtection);
		} catch (BadPasswordException e) {
            throw new InvalidPasswordException(e.getMessage());
		}
	}

	@Override
	public PdfDssDict getDSSDictionary() {
		PdfDict currentCatalog = new ITextPdfDict(pdfReader.getCatalog());
		return SingleDssDict.extract(currentCatalog);
	}

	@Override
	public Map<PdfSignatureDictionary, List<String>> extractSigDictionaries() {
		if (signatureDictionaryMap == null) {
			AcroFields acroFields = pdfReader.getAcroFields();
			
			Map<PdfSignatureDictionary, List<String>> pdfDictionaries = new LinkedHashMap<>();
			Map<Integer, PdfSigDictWrapper> pdfObjectDictMap = new LinkedHashMap<>();
			
			Map<String, Item> allFields = acroFields.getAllFields();
			List<String> names = acroFields.getSignedFieldNames();
			LOG.info("{} signature field(s) found", names.size());
			
			for (String name : names) {
				PdfDictionary pdfField = allFields.get(name).getMerged(0);
				int refNumber = pdfField.getAsIndirectObject(PdfName.V).getNumber();
				PdfSigDictWrapper signature = pdfObjectDictMap.get(refNumber);
				if (signature == null) {

					try {
						PdfDict dictionary = new ITextPdfDict(pdfField.getAsDict(PdfName.V));
						signature = new PdfSigDictWrapper(dictionary);
					} catch (Exception e) {
						LOG.warn("Unable to create a PdfSignatureDictionary for field with name '{}'", name, e);
						continue;
					}

					List<String> fieldNames = new ArrayList<>();
					fieldNames.add(name);
					pdfDictionaries.put(signature, fieldNames);
					pdfObjectDictMap.put(refNumber, signature);
				} else {
					List<String> fieldNameList = pdfDictionaries.get(signature);
					fieldNameList.add(name);
					LOG.warn("More than one field refers to the same signature dictionary: {}!", fieldNameList);

				}
			}
			signatureDictionaryMap = pdfDictionaries;
		}
		return signatureDictionaryMap;
	}

	@Override
	public void close() throws IOException {
		pdfReader.close();
	}

	@Override
	public boolean isSignatureCoversWholeDocument(PdfSignatureDictionary signatureDictionary) {
		AcroFields acroFields = pdfReader.getAcroFields();
		List<String> fieldNames = signatureDictionaryMap.get(signatureDictionary);
		if (Utils.isCollectionNotEmpty(fieldNames)) {
			return acroFields.signatureCoversWholeDocument(fieldNames.get(0));
		}
		throw new DSSException("Not applicable use of the method isSignatureCoversWholeDocument. The requested signatureDictionary does not exist!");
	}

}
