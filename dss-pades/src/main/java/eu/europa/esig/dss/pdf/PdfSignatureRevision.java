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

import java.util.List;

import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;

public class PdfSignatureRevision extends PdfCMSRevision {
	
	private final PdfDssDict dssDictionarySource;

	/**
	 * @param signatureDictionary
	 *            pdf signature dictionary wrapper
	 * @param dssDictionary
	 *            the DSS dictionary
	 * @param signatureFieldNames
	 *            list of signature field names
	 * @param originalBytes
	 *            the original bytes of the whole signed document
	 * @param coverCompleteRevision
	 *            identifies if the signature covers the whole revision
	 */
	public PdfSignatureRevision(PdfSignatureDictionary signatureDictionary, PdfDssDict dssDictionary, List<String> signatureFieldNames,
			byte[] originalBytes, boolean coverCompleteRevision) {
		super(signatureDictionary, signatureFieldNames, originalBytes, coverCompleteRevision);
		this.dssDictionarySource = dssDictionary;
	}

	public PdfDssDict getDssDictionary() {
		return dssDictionarySource;
	}

}
