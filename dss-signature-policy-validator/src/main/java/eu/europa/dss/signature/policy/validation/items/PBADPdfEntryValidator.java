package eu.europa.dss.signature.policy.validation.items;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import eu.europa.dss.signature.policy.asn1.ASN1PBADMandatedPdfSigDicEntries;
import eu.europa.dss.signature.policy.asn1.ASN1PBADPdfEntry;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class PBADPdfEntryValidator implements ItemValidator {
	
	private PAdESSignature sig;
	private ASN1PBADMandatedPdfSigDicEntries mandatedPdfEntries;
	private List<String> invalidEntries = new ArrayList<>();

	public PBADPdfEntryValidator(AdvancedSignature sig, ASN1PBADMandatedPdfSigDicEntries pbadPdfEntry) {
		this((PAdESSignature) sig, pbadPdfEntry);
	}

	public PBADPdfEntryValidator(PAdESSignature sig, ASN1PBADMandatedPdfSigDicEntries pbadPdfEntry) {
		this.sig = (PAdESSignature) sig;
		this.mandatedPdfEntries = pbadPdfEntry;
	}

	@Override
	public boolean validate() {
		PdfDict signatureDictionary = sig.getPdfSignatureInfo().getSignatureDictionary();
		for (ASN1PBADPdfEntry pdfEntry : mandatedPdfEntries.getPdfEntries()) {
			boolean isValid = (pdfEntry.getValue() == null)?
				signatureDictionary.hasAName(pdfEntry.getName()):
				signatureDictionary.hasANameWithValue(pdfEntry.getName(), new String(pdfEntry.getValue()));
				
			if (!isValid) {
				invalidEntries.add(pdfEntry.getName() + "=" + new String(pdfEntry.getValue()));
			}
		}
		return invalidEntries.isEmpty();
	}

	public List<String> getInvalidEntries() {
		return Collections.unmodifiableList(invalidEntries);
	}
}
