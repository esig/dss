/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents a merged result of extracted CRL binaries from different /DSS revisions of a PDF document
 *
 */
@SuppressWarnings("serial")
public class PdfCompositeDssDictCRLSource extends OfflineCRLSource {

    /** Composite map of CRL tokens extracted from different /DSS revisions by id */
    private final Map<PdfObjectKey, Set<CRLBinary>> crlBinaryByIdMap = new HashMap<>();

    /** Composite map of CRL tokens extracted from different /DSS revisions by encoded object binaries */
    private final Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<PdfObjectKey>> crlBinaryByObjectMap = new HashMap<>();

    /** Cached map of created CRLTokens and corresponding PDF object ids */
    private final Map<RevocationToken<CRL>, Set<PdfObjectKey>> crlTokenMap = new HashMap<>();

    /**
     * Default constructor instantiation an object with empty mpa of CRL token objects
     */
    public PdfCompositeDssDictCRLSource() {
        // empty
    }

    /**
     * This method allows adding CRL tokens extracted from a /DSS revision
     *
     * @param dssDictionary {@link PdfDssDict} representing a /DSS revision's content
     */
    public void populateFromDssDictionary(PdfDssDict dssDictionary) {
        extractDSSCRLs(dssDictionary);
        extractVRICRLs(dssDictionary);
    }

    /**
     * Extract the CRLs from the DSS dictionary
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    protected void extractDSSCRLs(PdfDssDict dssDictionary) {
        Map<PdfObjectKey, CRLBinary> dssCrlMap = dssDictionary.getCRLs();
        populateObjectsMap(dssCrlMap);
        for (CRLBinary crl : dssCrlMap.values()) {
            addBinary(crl, RevocationOrigin.DSS_DICTIONARY);
        }
    }

    /**
     * Extract the CRLs from all embedded VRI dictionaries
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    protected void extractVRICRLs(PdfDssDict dssDictionary) {
        if (dssDictionary != null) {
            List<PdfVriDict> vriDictList = dssDictionary.getVRIs();
            for (PdfVriDict vriDict : vriDictList) {
                populateObjectsMap(vriDict.getCRLs());
                extractVRICRLs(vriDict);
            }
        }
    }

    private void populateObjectsMap(Map<PdfObjectKey, CRLBinary> crlMap) {
        for (Map.Entry<PdfObjectKey, CRLBinary> entry : crlMap.entrySet()) {
            populateMapById(entry.getKey(), entry.getValue());
            populateMapByObject(entry.getKey(), entry.getValue());
        }
    }

    private void populateMapById(PdfObjectKey objectId, CRLBinary crlBinary) {
        Set<CRLBinary> crlBinaries = crlBinaryByIdMap.get(objectId);
        if (crlBinaries == null) {
            crlBinaries = new HashSet<>();
        }
        crlBinaries.add(crlBinary);
        crlBinaryByIdMap.put(objectId, crlBinaries);
    }

    private void populateMapByObject(PdfObjectKey objectId, CRLBinary crlBinary) {
        Set<PdfObjectKey> objectIds = crlBinaryByObjectMap.get(crlBinary);
        if (objectIds == null) {
            objectIds = new HashSet<>();
        }
        objectIds.add(objectId);
        crlBinaryByObjectMap.put(crlBinary, objectIds);
    }

    /**
     * Extract the CRLs from the VRI dictionary
     *
     * @param vriDictionary {@link PdfDssDict}
     */
    protected void extractVRICRLs(PdfVriDict vriDictionary) {
        if (vriDictionary != null) {
            for (Map.Entry<PdfObjectKey, CRLBinary> crlEntry : vriDictionary.getCRLs().entrySet()) {
                addBinary(crlEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
            }
        }
    }

    /**
     * This method returns a set of {@code CertificateToken}s with the given PDF object id
     *
     * @param objectId {@link PdfObjectKey} PDF id of the object to be extracted
     * @return set of {@link CRLBinary}s
     * @deprecated since DSS 6.2. To be removed.
     */
    @Deprecated
    protected Set<CRLBinary> getCRLBinariesByObjectId(PdfObjectKey objectId) {
        return crlBinaryByIdMap.get(objectId);
    }

    /**
     * Returns corresponding PDF object identifier for the extracted revocation token
     *
     * @param crlToken {@link eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken} to get id for
     * @return a set of {@link PdfObjectKey} identifiers
     */
    protected Set<PdfObjectKey> getRevocationTokenIds(RevocationToken<CRL> crlToken) {
        return crlTokenMap.get(crlToken);
    }

    @Override
    public void addRevocation(RevocationToken<CRL> token, EncapsulatedRevocationTokenIdentifier<CRL> binary) {
        super.addRevocation(token, binary);

        Set<PdfObjectKey> tokenBinaryObjectIds = getTokenBinaryObjectIds(binary);
        crlTokenMap.put(token, tokenBinaryObjectIds);
    }

    /**
     * Returns PDF object identifier for the provided binary
     *
     * @param binary {@link CRLBinary}
     * @return {@link Long} identifier
     */
    protected Set<PdfObjectKey> getTokenBinaryObjectIds(EncapsulatedRevocationTokenIdentifier<CRL> binary) {
        return crlBinaryByObjectMap.get(binary);
    }

}
