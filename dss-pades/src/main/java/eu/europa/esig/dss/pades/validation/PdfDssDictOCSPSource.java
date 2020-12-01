package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class PdfDssDictOCSPSource extends OfflineOCSPSource {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESOCSPSource.class);

    private final PdfDssDict dssDictionary;

    private final String vriDictionaryName;

    private transient Map<Long, BasicOCSPResp> ocspMap;

    public PdfDssDictOCSPSource(final PdfDssDict dssDictionary) {
        this(dssDictionary, null);
    }

    PdfDssDictOCSPSource (final PdfDssDict dssDictionary, final String vriDictionaryName) {
        this.dssDictionary = dssDictionary;
        this.vriDictionaryName = vriDictionaryName;
        extractDSSOCSPs();
        extractVRIOCSPs();
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
    private Map<Long, BasicOCSPResp> getDssOcspMap() {
        if (dssDictionary != null) {
            ocspMap = dssDictionary.getOCSPs();
            return ocspMap;
        }
        return Collections.emptyMap();
    }

    private void extractDSSOCSPs() {
        for (BasicOCSPResp basicOCSPResp : getDssOcspMap().values()) {
            addBinary(OCSPResponseBinary.build(basicOCSPResp), RevocationOrigin.DSS_DICTIONARY);
        }
    }

    protected void extractVRIOCSPs() {
        if (dssDictionary != null) {
            List<PdfVRIDict> vriDictList = dssDictionary.getVRIs();
            if (Utils.isCollectionNotEmpty(vriDictList)) {
                for (PdfVRIDict vriDict : vriDictList) {
                    if (vriDictionaryName == null || vriDictionaryName.equals(vriDict.getName())) {
                        extractVRIOCSPs(vriDict);
                    }
                }
            }
        }
    }

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
