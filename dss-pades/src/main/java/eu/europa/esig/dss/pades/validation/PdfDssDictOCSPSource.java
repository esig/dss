package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The OCSP source extracted from a DSS dictionary
 */
public class PdfDssDictOCSPSource extends OfflineOCSPSource {

    /** The map of PDF object ids and corresponding OCSP binaries */
    private transient Map<Long, BasicOCSPResp> ocspMap;

    /**
     * Default constructor
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    public PdfDssDictOCSPSource(PdfDssDict dssDictionary) {
        extractDSSOCSPs(dssDictionary);
        extractVRIOCSPs(dssDictionary);
    }

    /**
     * Empty constructor
     */
    PdfDssDictOCSPSource() {
    }

    /**
     * Returns a map of all OCSP entries contained in DSS dictionary or into nested
     * VRI dictionaries
     *
     * @return a map of BasicOCSPResp with their object ids
     */
    public Map<Long, BasicOCSPResp> getOcspMap() {
        if (ocspMap != null) {
            return ocspMap;
        }
        return Collections.emptyMap();
    }

    /**
     * This method returns a map with the object number and the ocsp response
     *
     * @return a map with the object number and the ocsp response
     */
    private Map<Long, BasicOCSPResp> getDssOcspMap(PdfDssDict dssDictionary) {
        if (dssDictionary != null) {
            ocspMap = dssDictionary.getOCSPs();
            return ocspMap;
        }
        return Collections.emptyMap();
    }

    /**
     * Extract the OCSPs from the DSS dictionary
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    protected void extractDSSOCSPs(PdfDssDict dssDictionary) {
        Map<Long, BasicOCSPResp> dssOcspMap = getDssOcspMap(dssDictionary);
        for (BasicOCSPResp basicOCSPResp : dssOcspMap.values()) {
            addBinary(OCSPResponseBinary.build(basicOCSPResp), RevocationOrigin.DSS_DICTIONARY);
        }
    }

    /**
     * Extract the OCSPs from all embedded VRI dictionaries
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    protected void extractVRIOCSPs(PdfDssDict dssDictionary) {
        if (dssDictionary != null) {
            List<PdfVRIDict> vriDictList = dssDictionary.getVRIs();
            if (Utils.isCollectionNotEmpty(vriDictList)) {
                for (PdfVRIDict vriDict : vriDictList) {
                    extractVRIOCSPs(vriDict);
                }
            }
        }
    }

    /**
     * Extract the OCSPs from the VRI dictionary
     *
     * @param vriDictionary {@link PdfDssDict}
     */
    protected void extractVRIOCSPs(PdfVRIDict vriDictionary) {
        if (vriDictionary != null) {
            for (Map.Entry<Long, BasicOCSPResp> ocspEntry : vriDictionary.getOCSPs().entrySet()) {
                if (!ocspMap.containsKey(ocspEntry.getKey())) {
                    ocspMap.put(ocspEntry.getKey(), ocspEntry.getValue());
                }
                addBinary(OCSPResponseBinary.build(ocspEntry.getValue()), RevocationOrigin.VRI_DICTIONARY);
            }
        }
    }

}
