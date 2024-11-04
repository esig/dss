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
package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The certificate source extracted from a DSS dictionary
 */
public class PdfDssDictCertificateSource extends TokenCertificateSource {

    private static final long serialVersionUID = 7254611440571170316L;

    /** Merged certificate source combined from all /DSS revisions */
    private final PdfCompositeDssDictCertificateSource compositeCertificateSource;

    /** The DSS dictionary */
    private final PdfDssDict dssDictionary;

    /** Name of the signature's VRI dictionary, when applicable */
    private final String relatedVRIDictionaryName;

    /**
     * Default constructor
     *
     * @param compositeCertificateSource {@link PdfCompositeDssDictCertificateSource}
     * @param dssDictionary {@link PdfDssDict}
     */
    public PdfDssDictCertificateSource(final PdfCompositeDssDictCertificateSource compositeCertificateSource,
                                       final PdfDssDict dssDictionary) {
        this(compositeCertificateSource, dssDictionary, null);
    }

    /**
     * Default constructor with VRI name (to be used for a signature)
     *
     * @param compositeCertificateSource {@link PdfCompositeDssDictCertificateSource}
     * @param dssDictionary {@link PdfDssDict}
     * @param vriDictionaryName {@link String}
     */
    public PdfDssDictCertificateSource(final PdfCompositeDssDictCertificateSource compositeCertificateSource,
                                       final PdfDssDict dssDictionary, final String vriDictionaryName) {
        this.compositeCertificateSource = compositeCertificateSource;
        this.dssDictionary = dssDictionary;
        this.relatedVRIDictionaryName = vriDictionaryName;

        extractFromDssDictSource();
    }

    private void extractFromDssDictSource() {
        for (CertificateToken certToken : getDSSDictionaryCertValues()) {
            addCertificate(certToken, CertificateOrigin.DSS_DICTIONARY);
        }
        for (CertificateToken certToken : getVRIDictionaryCertValues()) {
            addCertificate(certToken, CertificateOrigin.VRI_DICTIONARY);
        }
    }

    /**
     * Gets a map of PDF object ids and corresponding certificate tokens
     *
     * @return a map of PDF object ids and corresponding certificate tokens
     */
    public Map<PdfObjectKey, CertificateToken> getCertificateMap() {
        if (dssDictionary != null) {
            Map<PdfObjectKey, CertificateToken> dssCerts = dssDictionary.getCERTs();
            List<PdfVriDict> vriDicts = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
            for (PdfVriDict vriDict : vriDicts) {
                dssCerts.putAll(vriDict.getCERTs());
            }
            return dssCerts;
        }
        return Collections.emptyMap();
    }

    /**
     * Gets list of DSS dictionary certificate tokens
     *
     * @return a list of {@link CertificateToken}s
     */
    public List<CertificateToken> getDSSDictionaryCertValues() {
        if (dssDictionary != null) {
            return getCertificatesByKeys(dssDictionary.getCERTs().keySet());
        }
        return Collections.emptyList();
    }

    /**
     * Gets list of certificate tokens extracted from all VRI dictionaries
     *
     * @return a list of {@link CertificateToken}s
     */
    public List<CertificateToken> getVRIDictionaryCertValues() {
        if (dssDictionary != null) {
            Set<PdfObjectKey> certKeys = new HashSet<>();
            List<PdfVriDict> vris = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
            for (PdfVriDict vri : vris) {
                certKeys.addAll(vri.getCERTs().keySet());
            }
            return getCertificatesByKeys(certKeys);
        }
        return Collections.emptyList();
    }

    private List<CertificateToken> getCertificatesByKeys(Collection<PdfObjectKey> objectIds) {
        List<CertificateToken> certificateTokens = new ArrayList<>();
        for (PdfObjectKey objectId : objectIds) {
            certificateTokens.addAll(compositeCertificateSource.getCertificateTokensByObjectId(objectId));
        }
        return certificateTokens;
    }

}
