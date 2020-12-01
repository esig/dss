package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.util.ArrayList;

/**
 * Specific class for a PDF TimestampToken
 *
 */
@SuppressWarnings("serial")
public class PdfTimestampToken extends TimestampToken {

	/**
	 * The related PDF revision
	 */
	private PdfDocTimestampRevision pdfRevision;

	/**
	 * The default constructor
	 * 
	 * @param pdfTimestampRevision {@link PdfDocTimestampRevision} related to the current
	 *                             TimestampToken
	 * @throws TSPException if a timestamp parsing issue occurs
	 * @throws IOException  if a reading exception occurs
	 * @throws CMSException if a CMS exception occurs
	 */
	public PdfTimestampToken(final PdfDocTimestampRevision pdfTimestampRevision)
			throws TSPException, IOException, CMSException {
		super(pdfTimestampRevision.getPdfSigDictInfo().getCMSSignedData(), TimestampType.DOCUMENT_TIMESTAMP, new ArrayList<>());
		this.pdfRevision = pdfTimestampRevision;
	}

	/**
	 * Returns the current PDF timestamp revision
	 * 
	 * @return {@link PdfRevision}
	 */
	public PdfDocTimestampRevision getPdfRevision() {
		return pdfRevision;
	}

}
