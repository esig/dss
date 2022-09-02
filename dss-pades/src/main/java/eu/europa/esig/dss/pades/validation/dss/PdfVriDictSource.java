package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;

/**
 * This class extracts special information from a VRI dictionary
 *
 */
public class PdfVriDictSource {

    private static final Logger LOG = LoggerFactory.getLogger(PdfVriDictSource.class);

    /** The DSS dictionary */
    private final PdfVriDict pdfVriDict;

    /**
     * Default constructor
     *
     * @param dssDictionary {@link PdfDssDict} DSS dictionary
     * @param vriDictionaryName {@link String} SHA-1 of the signature name
     */
    public PdfVriDictSource(final PdfDssDict dssDictionary, final String vriDictionaryName) {
        List<PdfVriDict> vris = PAdESUtils.getVRIsWithName(dssDictionary, vriDictionaryName);
        if (Utils.collectionSize(vris) == 1) {
            this.pdfVriDict = vris.get(0);
        } else {
            this.pdfVriDict = null;
        }
    }

    /**
     * Returns VRI creation time extracted from 'TU' field
     *
     * @return {@link Date}
     */
    public Date getVRICreationTime() {
        if (pdfVriDict != null) {
            return pdfVriDict.getTUTime();
        }
        return null;
    }

    /**
     * Returns a timestamp token extracted from the VRI dictionary from 'TS' field
     *
     * @return {@link TimestampToken}
     */
    public TimestampToken getTimestampToken() {
        if (pdfVriDict != null) {
            try {
                byte[] tsStream = pdfVriDict.getTSStream();
                if (Utils.isArrayNotEmpty(tsStream)) {
                    return new TimestampToken(pdfVriDict.getTSStream(), TimestampType.VRI_TIMESTAMP);
                }

            } catch (Exception e) {
                LOG.warn("An error occurred while extracting 'TS' timestamp from the corresponding /VRI dictionary : {}", e.getMessage());
            }
        }
        return null;
    }

}
