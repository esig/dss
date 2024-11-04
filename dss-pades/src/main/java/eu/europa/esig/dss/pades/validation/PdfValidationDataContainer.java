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
package eu.europa.esig.dss.pades.validation;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * A PDF implementation if {@code ValidationDataContainer} containing a validation data
 * to be incorporated within a PDF document
 *
 */
public class PdfValidationDataContainer extends ValidationDataContainer {

    /** A list of PDF DSS revisions */
    private final Collection<PdfDocDssRevision> pdfDssRevisions;

    /** Cached map of known object references from a PDF */
    private Map<String, PdfObjectKey> knownObjects;

    /**
     * Default constructor
     *
     * @param pdfDssRevisions a collection of {@link PdfDocDssRevision}s extracted from a document
     */
    public PdfValidationDataContainer(final Collection<PdfDocDssRevision> pdfDssRevisions) {
        this.pdfDssRevisions = pdfDssRevisions;
    }

    /**
     * This method builds a map of token identifiers and their unique references within a PDF document
     * from a list of extracted PdfRevisions
     *
     * @return a map of token ids and their corresponding PDF references
     */
    public Map<String, PdfObjectKey> getKnownObjectsMap() {
        if (knownObjects == null) {
            knownObjects = new HashMap<>();

            if (Utils.isCollectionNotEmpty(pdfDssRevisions)) {
                for (PdfDocDssRevision dssRevision : pdfDssRevisions) {
                    PdfDssDictCertificateSource certificateSource = dssRevision.getCertificateSource();
                    Map<PdfObjectKey, CertificateToken> storedCertificates = certificateSource.getCertificateMap();
                    for (Map.Entry<PdfObjectKey, CertificateToken> certEntry : storedCertificates.entrySet()) {
                        String tokenKey = getTokenKey(certEntry.getValue());
                        if (!knownObjects.containsKey(tokenKey)) { // keeps the really first occurrence
                            knownObjects.put(tokenKey, certEntry.getKey());
                        }
                    }

                    PdfDssDictCRLSource crlSource = dssRevision.getCRLSource();
                    Map<PdfObjectKey, CRLBinary> storedCrls = crlSource.getCrlMap();
                    for (Map.Entry<PdfObjectKey, CRLBinary> crlEntry : storedCrls.entrySet()) {
                        String tokenKey = crlEntry.getValue().asXmlId();
                        if (!knownObjects.containsKey(tokenKey)) { // keeps the really first occurrence
                            knownObjects.put(tokenKey, crlEntry.getKey());
                        }
                    }

                    PdfDssDictOCSPSource ocspSource = dssRevision.getOCSPSource();
                    Map<PdfObjectKey, OCSPResponseBinary> storedOcspResps = ocspSource.getOcspMap();
                    for (Map.Entry<PdfObjectKey, OCSPResponseBinary> ocspEntry : storedOcspResps.entrySet()) {
                        OCSPResponseBinary ocspResponseBinary = ocspEntry.getValue();
                        String tokenKey = ocspResponseBinary.getDSSId().asXmlId();
                        if (!knownObjects.containsKey(tokenKey)) { // keeps the really first occurrence
                            knownObjects.put(tokenKey, ocspEntry.getKey());
                        }
                    }
                }
            }
        }

        return knownObjects;
    }

    /**
     * Returns a reference corresponding to the given token from the PDF document, if present
     *
     * @param token {@link Token}
     * @return the token reference identifier when present, null otherwise
     */
    public PdfObjectKey getTokenReference(Token token) {
        String tokenKey = getTokenKey(token);
        return getKnownObjectsMap().get(tokenKey);
    }

    /**
     * Gets a token key (DSS Id or EntityKey Id for a CertificateToken)
     *
     * @param token {@link Token}
     * @return {@link String} base64 encoded SHA-256 digest
     */
    public String getTokenKey(Token token) {
        if (token instanceof CertificateToken) {
            return ((CertificateToken) token).getEntityKey().asXmlId();
        }
        return token.getDSSIdAsString();
    }

}
