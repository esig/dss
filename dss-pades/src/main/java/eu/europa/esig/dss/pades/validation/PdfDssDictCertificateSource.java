package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PdfDssDictCertificateSource extends TokenCertificateSource {

    private final PdfDssDict dssDictionary;

    public PdfDssDictCertificateSource(final PdfDssDict dssDictionary) {
        this.dssDictionary = dssDictionary;
        extractFromDSSDict();
    }

    private void extractFromDSSDict() {
        for (CertificateToken certToken : getDSSDictionaryCertValues()) {
            addCertificate(certToken, CertificateOrigin.DSS_DICTIONARY);
        }
        for (CertificateToken certToken : getVRIDictionaryCertValues()) {
            addCertificate(certToken, CertificateOrigin.VRI_DICTIONARY);
        }
    }

    public Map<Long, CertificateToken> getCertificateMap() {
        if (dssDictionary != null) {
            Map<Long, CertificateToken> dssCerts = dssDictionary.getCERTs();
            List<PdfVRIDict> vriDicts = dssDictionary.getVRIs();
            if (Utils.isCollectionNotEmpty(vriDicts)) {
                for (PdfVRIDict vriDict : vriDicts) {
                    dssCerts.putAll(vriDict.getCERTs());
                }
            }
            return dssCerts;
        }
        return Collections.emptyMap();
    }

    public List<CertificateToken> getDSSDictionaryCertValues() {
        if (dssDictionary != null) {
            Map<Long, CertificateToken> dssCerts = dssDictionary.getCERTs();
            return new ArrayList<>(dssCerts.values());
        }
        return Collections.emptyList();
    }

    public List<CertificateToken> getVRIDictionaryCertValues() {
        if (dssDictionary != null) {
            Map<Long, CertificateToken> vriCerts = new HashMap<>();
            List<PdfVRIDict> vris = dssDictionary.getVRIs();
            if (vris != null) {
                for (PdfVRIDict vri : vris) {
                    vriCerts.putAll(vri.getCERTs());
                }
            }
            return new ArrayList<>(vriCerts.values());
        }
        return Collections.emptyList();
    }

}
