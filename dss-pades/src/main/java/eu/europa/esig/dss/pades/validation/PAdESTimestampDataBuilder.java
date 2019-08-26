package eu.europa.esig.dss.pades.validation;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.cades.validation.CAdESTimestampDataBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class PAdESTimestampDataBuilder extends CAdESTimestampDataBuilder {
	
	private final PdfSignatureInfo pdfSignatureInfo;
	
	private List<TimestampToken> signatureTimestamps = new ArrayList<TimestampToken>();

	public PAdESTimestampDataBuilder(PdfSignatureInfo pdfSignatureInfo, final SignerInformation signerInformation, List<DSSDocument> detacheDocuments) {
		super(signerInformation, detacheDocuments);
		this.pdfSignatureInfo = pdfSignatureInfo;
	}
	
	public void setSignatureTimestamps(List<TimestampToken> signatureTimestamps) {
		this.signatureTimestamps = signatureTimestamps;
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken) {
		for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
			if (signatureInfo instanceof PdfDocTimestampInfo) {
				PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
				if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
					final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
					return signedDocumentBytes;
				}
			}
		}
		if (signatureTimestamps.contains(timestampToken)) {
			return super.getSignatureTimestampData(timestampToken);
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken) {
		/* Not applicable for PAdES */
		return null;
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken) {
		/* Not applicable for PAdES */
		return null;
	}

	@Override
	public byte[] getArchiveTimestampData(TimestampToken timestampToken) {
		for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
			if (signatureInfo instanceof PdfDocTimestampInfo) {
				PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
				if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
					final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
					return signedDocumentBytes;
				}
			}
		}
		throw new DSSException("Timestamp Data not found");
	}

}
