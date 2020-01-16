package eu.europa.esig.dss.pades.timestamp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

public class PAdESTimestampService {

	private final TSPSource tspSource;
	private final PDFSignatureService pdfSignatureService;

	public PAdESTimestampService(TSPSource tspSource, PDFSignatureService pdfSignatureService) {
		this.tspSource = tspSource;
		this.pdfSignatureService = pdfSignatureService;
	}
	
	public DSSDocument timestampDocument(final DSSDocument document, final PAdESTimestampParameters params) throws DSSException {
		final DigestAlgorithm timestampDigestAlgorithm = params.getDigestAlgorithm();
		final byte[] digest = pdfSignatureService.digest(document, params);
		final TimestampBinary timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getDEREncoded(timeStampToken);
		return pdfSignatureService.sign(document, encoded, params);
	}

}
