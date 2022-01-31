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
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents a merged result of extracted certificate sources from /DSS revisions of a PDF document
 *
 */
@SuppressWarnings("serial")
public class PdfCompositeDssDictCertificateSource extends TokenCertificateSource {

    /** Composite map of certificate tokens extracted from different /DSS revisions */
    private final Map<Long, Set<CertificateToken>> certMap = new HashMap<>();

    /**
     * This method allows adding certificates extracted from a /DSS revision
     *
     * @param dssDictionary {@link PdfDssDict} representing a /DSS revision's content
     */
    public void populateFromDssDictionary(PdfDssDict dssDictionary) {
        for (CertificateToken certToken : getDSSDictionaryCertValues(dssDictionary)) {
            addCertificate(certToken, CertificateOrigin.DSS_DICTIONARY);
        }
        for (CertificateToken certToken : getVRIDictionaryCertValues(dssDictionary)) {
            addCertificate(certToken, CertificateOrigin.VRI_DICTIONARY);
        }
    }

    /**
     * Gets list of DSS dictionary certificate tokens
     *
     * @param dssDictionary {@link PdfDssDict} to extract certificates from
     * @return a list of {@link CertificateToken}s
     */
    private List<CertificateToken> getDSSDictionaryCertValues(PdfDssDict dssDictionary) {
        if (dssDictionary != null) {
            Map<Long, CertificateToken> dssCerts = dssDictionary.getCERTs();
            populateObjectsMap(dssCerts);
            return new ArrayList<>(dssCerts.values());
        }
        return Collections.emptyList();
    }

    /**
     * Gets list of certificate tokens extracted from all VRI dictionaries
     *
     * @param dssDictionary {@link PdfDssDict} to extract certificates from
     * @return a list of {@link CertificateToken}s
     */
    private List<CertificateToken> getVRIDictionaryCertValues(PdfDssDict dssDictionary) {
        if (dssDictionary != null) {
            Map<Long, CertificateToken> vriCerts = new HashMap<>();
            List<PdfVRIDict> vris = dssDictionary.getVRIs();
            if (vris != null) {
                for (PdfVRIDict vri : vris) {
                    vriCerts.putAll(vri.getCERTs());
                }
            }
            populateObjectsMap(vriCerts);
            return new ArrayList<>(vriCerts.values());
        }
        return Collections.emptyList();
    }

    private void populateObjectsMap(Map<Long, CertificateToken> certificateTokenMap) {
        for (Map.Entry<Long, CertificateToken> entry : certificateTokenMap.entrySet()) {
            Set<CertificateToken> certificateTokens = certMap.get(entry.getKey());
            if (certificateTokens == null) {
                certificateTokens = new HashSet<>();
            }
            certificateTokens.add(entry.getValue());
            certMap.put(entry.getKey(), certificateTokens);
        }
    }

    /**
     * This method returns a set of {@code CertificateToken}s with the given PDF object id
     *
     * @param objectId {@link Long} PDF id of the object to be extracted
     * @return set of {@link CertificateToken}s
     */
    protected Set<CertificateToken> getCertificateTokensByObjectId(Long objectId) {
        return certMap.get(objectId);
    }

}
