package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class PdfDssDictCRLSource extends OfflineCRLSource {

    private final PdfDssDict dssDictionary;

    private final String vriDictionaryName;

    private Map<Long, CRLBinary> crlMap;

    public PdfDssDictCRLSource(final PdfDssDict dssDictionary) {
        this(dssDictionary, null);
    }

    PdfDssDictCRLSource(final PdfDssDict dssDictionary, final String vriDictionaryName) {
        this.dssDictionary = dssDictionary;
        this.vriDictionaryName = vriDictionaryName;
        extractDSSCRLs();
        extractVRICRLs();
    }

    /**
     * Returns a map of all CRL entries contained in DSS dictionary or into nested
     * VRI dictionaries
     *
     * @return a map of CRL binaries with their object ids
     */
    public Map<Long, CRLBinary> getCrlMap() {
        if (crlMap != null) {
            return crlMap;
        }
        return Collections.emptyMap();
    }

    private Map<Long, CRLBinary> getDssCrlMap() {
        if (dssDictionary != null) {
            crlMap = dssDictionary.getCRLs();
            return crlMap;
        }
        return Collections.emptyMap();
    }

    protected void extractDSSCRLs() {
        for (CRLBinary crl : getDssCrlMap().values()) {
            addBinary(crl, RevocationOrigin.DSS_DICTIONARY);
        }
    }

    protected void extractVRICRLs() {
        if (dssDictionary != null) {
            List<PdfVRIDict> vriDictList = dssDictionary.getVRIs();
            if (Utils.isCollectionNotEmpty(vriDictList)) {
                for (PdfVRIDict vriDict : vriDictList) {
                    if (vriDictionaryName == null || vriDictionaryName.equals(vriDict.getName())) {
                        extractVRICRLs(vriDict);
                    }
                }
            }
        }
    }

    protected void extractVRICRLs(PdfVRIDict vriDictionary) {
        if (vriDictionary != null) {
            for (Map.Entry<Long, CRLBinary> crlEntry : vriDictionary.getCRLs().entrySet()) {
                if (!crlMap.containsKey(crlEntry.getKey())) {
                    crlMap.put(crlEntry.getKey(), crlEntry.getValue());
                }
                addBinary(crlEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
            }
        }
    }

}
