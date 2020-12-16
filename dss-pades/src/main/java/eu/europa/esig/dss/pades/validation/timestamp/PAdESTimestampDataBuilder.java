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
package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.cades.validation.timestamp.CAdESTimestampDataBuilder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.List;

public class PAdESTimestampDataBuilder extends CAdESTimestampDataBuilder {
	
	private final List<PdfRevision> documentRevisions;
	
	private List<TimestampToken> signatureTimestamps = new ArrayList<>();

	public PAdESTimestampDataBuilder(final List<PdfRevision> documentRevisions, final PAdESSignature signature,
									 final ListCertificateSource certificateSource) {
		super(signature, certificateSource);
		this.documentRevisions = documentRevisions;
	}
	
	public void setSignatureTimestamps(List<TimestampToken> signatureTimestamps) {
		this.signatureTimestamps = signatureTimestamps;
	}

	@Override
	public DSSDocument getSignatureTimestampData(final TimestampToken timestampToken) {
		DSSDocument signedData = getSignedDataInPDFRevisions(timestampToken);
		if (signedData != null) {
			return signedData;
		}
		if (signatureTimestamps.contains(timestampToken)) {
			return super.getSignatureTimestampData(timestampToken);
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public DSSDocument getTimestampX1Data(final TimestampToken timestampToken) {
		/* Not applicable for PAdES */
		return null;
	}

	@Override
	public DSSDocument getTimestampX2Data(final TimestampToken timestampToken) {
		/* Not applicable for PAdES */
		return null;
	}

	@Override
	public DSSDocument getArchiveTimestampData(TimestampToken timestampToken) {
		DSSDocument signedData = getSignedDataInPDFRevisions(timestampToken);
		if (signedData != null) {
			return signedData;
		}
		throw new DSSException("Timestamp Data not found");
	}

	private DSSDocument getSignedDataInPDFRevisions(final TimestampToken timestampToken) {
		for (final PdfRevision signatureInfo : documentRevisions) {
			if (signatureInfo instanceof PdfDocTimestampRevision) {
				PdfDocTimestampRevision pdfTimestampInfo = (PdfDocTimestampRevision) signatureInfo;
				if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
					final byte[] signedDocumentBytes = pdfTimestampInfo.getRevisionCoveredBytes();
					return new InMemoryDocument(signedDocumentBytes);
				}
			}
		}
		return null;
	}

}
