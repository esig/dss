package eu.europa.esig.dss.pdf;

import java.io.IOException;
import java.util.Date;

import eu.europa.esig.dss.DSSException;

public class PdfSigDict {

	private PdfDict dictionay;

	public PdfSigDict(PdfDict dictionay) {
		this.dictionay = dictionay;
	}

	public String getContactInfo() {
		return dictionay.getStringValue("ContactInfo");
	}

	public String getReason() {
		return dictionay.getStringValue("Reason");
	}

	public String getLocation() {
		return dictionay.getStringValue("Location");
	}

	public Date getSigningDate() {
		return dictionay.getDateValue("M");
	}

	public String getFilter() {
		return dictionay.getNameValue("Filter");
	}

	public String getSubFilter() {
		return dictionay.getNameValue("SubFilter");
	}

	public byte[] getContents() {
		try {
			return dictionay.get("Contents");
		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the signature content", e);
		}
	}

	public int[] getByteRange() {
		PdfArray byteRangeArray = dictionay.getAsArray("ByteRange");
		int arraySize = byteRangeArray.size();
		int[] result = new int[arraySize];
		for (int i = 0; i < arraySize; i++) {
			try {
				result[i] = byteRangeArray.getInt(i);
			} catch (IOException e) {
				throw new DSSException("Unable to retrieve the byterange", e);
			}
		}
		return result;
	}
}
