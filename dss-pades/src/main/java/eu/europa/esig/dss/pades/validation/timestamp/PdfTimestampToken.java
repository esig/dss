package eu.europa.esig.dss.pades.validation.timestamp;

import java.io.IOException;
import java.util.ArrayList;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

/**
 * Specific class for a PDF TimestampToken
 *
 */
@SuppressWarnings("serial")
public class PdfTimestampToken extends TimestampToken {

	/**
	 * The related PDF revision
	 */
	private PdfRevision pdfRevision;

	/**
	 * The default constructor
	 * 
	 * @param pdfTimestampRevision {@link PdfRevision} related to the current
	 *                             TimestampToken
	 * @param type                 {@link TimestampType}
	 * @throws TSPException if a timestamp parsing issue occurs
	 * @throws IOException  if a reading exception occurs
	 * @throws CMSException if a CMS exception occurs
	 */
	public PdfTimestampToken(final PdfRevision pdfTimestampRevision, final TimestampType type)
			throws TSPException, IOException, CMSException {
		super(pdfTimestampRevision.getPdfSigDictInfo().getCMSSignedData(), type, new ArrayList<TimestampedReference>(),
				TimestampLocation.DOC_TIMESTAMP);
		this.pdfRevision = pdfTimestampRevision;
	}

	/**
	 * Returns the current PDF timestamp revision
	 * 
	 * @return {@link PdfRevision}
	 */
	public PdfRevision getPdfRevision() {
		return pdfRevision;
	}

}
