/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.signature.policy.PBADMandatedPdfSigDicEntries;
import eu.europa.esig.dss.signature.policy.PBADPdfEntry;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class PBADPdfEntryValidator implements ItemValidator {
	
	private PAdESSignature sig;
	private PBADMandatedPdfSigDicEntries mandatedPdfEntries;
	private List<String> invalidEntries = new ArrayList<>();

	public PBADPdfEntryValidator(AdvancedSignature sig, PBADMandatedPdfSigDicEntries pbadPdfEntry) {
		this((PAdESSignature) sig, pbadPdfEntry);
	}

	public PBADPdfEntryValidator(PAdESSignature sig, PBADMandatedPdfSigDicEntries pbadPdfEntry) {
		this.sig = (PAdESSignature) sig;
		this.mandatedPdfEntries = pbadPdfEntry;
	}

	@Override
	public boolean validate() {
		PdfDict signatureDictionary = sig.getPdfSignatureInfo().getSignatureDictionary();
		for (PBADPdfEntry pdfEntry : mandatedPdfEntries.getPdfEntries()) {
			boolean isValid = (pdfEntry.getValue() == null)?
				signatureDictionary.hasAName(pdfEntry.getName()):
				signatureDictionary.hasANameWithValue(pdfEntry.getName(), new String(pdfEntry.getValue()));
				
			if (!isValid) {
				try {
					byte[] value = signatureDictionary.get(pdfEntry.getName());
					invalidEntries.add(pdfEntry.getName() + "=" + (value == null? null: new String(value)));
				} catch (IOException e) {
					invalidEntries.add(pdfEntry.getName() + "= <error parsing value>");
				}
			}
		}
		return invalidEntries.isEmpty();
	}
	
	public String getErrorDetail() {
		if (invalidEntries.isEmpty()) { 
			return "";
		}
		
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("Invalid PDF entries ");
		for (String key : invalidEntries) {
			stringBuilder.append(" ").append(key).append(",");
		}
		stringBuilder.setLength(stringBuilder.length() - 1);
		return stringBuilder.toString();
	}

	public List<String> getInvalidEntries() {
		return Collections.unmodifiableList(invalidEntries);
	}
}
