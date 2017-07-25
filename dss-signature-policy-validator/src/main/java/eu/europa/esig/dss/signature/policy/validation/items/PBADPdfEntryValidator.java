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
					invalidEntries.add(pdfEntry.getName() + "=" + new String(signatureDictionary.get(pdfEntry.getName())));
				} catch (IOException e) {
					invalidEntries.add(pdfEntry.getName() + "= <error parsing value>");
				}
			}
		}
		return invalidEntries.isEmpty();
	}

	public List<String> getInvalidEntries() {
		return Collections.unmodifiableList(invalidEntries);
	}
}
