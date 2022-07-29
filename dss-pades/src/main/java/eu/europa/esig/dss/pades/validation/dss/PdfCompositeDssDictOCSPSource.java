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

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Represents a merged result of extracted OCSP binaries from different /DSS revisions of a PDF document
 *
 */
@SuppressWarnings("serial")
public class PdfCompositeDssDictOCSPSource extends OfflineOCSPSource {

    /** Composite map of OCSP tokens extracted from different /DSS revisions by object id */
    private final Map<Long, Set<OCSPResponseBinary>> ocspBinaryByIdMap = new HashMap<>();

    /** Composite map of OCSP tokens extracted from different /DSS revisions by encoded object binaries */
    private final Map<EncapsulatedRevocationTokenIdentifier<OCSP>, Set<Long>> ocspBinaryByObjectMap = new HashMap<>();

    /** Cached map of created OCSPTokens and corresponding PDF object ids */
    private final Map<RevocationToken<OCSP>, Set<Long>> ocspTokenMap = new HashMap<>();

    /**
     * Default constructor instantiation an object with empty mpa of OCSP token objects
     */
    public PdfCompositeDssDictOCSPSource() {
    }

    /**
     * This method allows adding OCSP tokens extracted from a /DSS revision
     *
     * @param dssDictionary {@link PdfDssDict} representing a /DSS revision's content
     */
    public void populateFromDssDictionary(PdfDssDict dssDictionary) {
        extractDSSOCSPs(dssDictionary);
        extractVRIOCSPs(dssDictionary);
    }

    /**
     * Extract the OCSPs from the DSS dictionary
     *
     * @param dssDictionary {@link PdfDssDict}
     */
    protected void extractDSSOCSPs(PdfDssDict dssDictionary) {
        Map<Long, OCSPResponseBinary> dssOCSPMap = dssDictionary.getOCSPs();
        populateObjectsMap(dssOCSPMap);
        for (OCSPResponseBinary OCSP : dssOCSPMap.values()) {
            addBinary(OCSP, RevocationOrigin.DSS_DICTIONARY);
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
            for (PdfVRIDict vriDict : vriDictList) {
                populateObjectsMap(vriDict.getOCSPs());
                extractVRIOCSPs(vriDict);
            }
        }
    }

    private void populateObjectsMap(Map<Long, OCSPResponseBinary> ocspMap) {
        for (Map.Entry<Long, OCSPResponseBinary> entry : ocspMap.entrySet()) {
            populateMapById(entry.getKey(), entry.getValue());
            populateMapByObject(entry.getKey(), entry.getValue());
        }
    }

    private void populateMapById(Long objectId, OCSPResponseBinary ocspBinary) {
        Set<OCSPResponseBinary> ocspBinaries = ocspBinaryByIdMap.get(objectId);
        if (ocspBinaries == null) {
            ocspBinaries = new HashSet<>();
        }
        ocspBinaries.add(ocspBinary);
        ocspBinaryByIdMap.put(objectId, ocspBinaries);
    }

    private void populateMapByObject(Long objectId, OCSPResponseBinary ocspBinary) {
        Set<Long> objectIds = ocspBinaryByObjectMap.get(ocspBinary);
        if (objectIds == null) {
            objectIds = new HashSet<>();
        }
        objectIds.add(objectId);
        ocspBinaryByObjectMap.put(ocspBinary, objectIds);
    }

    /**
     * Extract the OCSPs from the VRI dictionary
     *
     * @param vriDictionary {@link PdfDssDict}
     */
    protected void extractVRIOCSPs(PdfVRIDict vriDictionary) {
        if (vriDictionary != null) {
            for (Map.Entry<Long, OCSPResponseBinary> OCSPEntry : vriDictionary.getOCSPs().entrySet()) {
                addBinary(OCSPEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
            }
        }
    }

    /**
     * This method returns a set of {@code CertificateToken}s with the given PDF object id
     *
     * @param objectId {@link Long} PDF id of the object to be extracted
     * @return set of {@link OCSPResponseBinary}s
     */
    protected Set<OCSPResponseBinary> getOCSPBinariesByObjectId(Long objectId) {
        return ocspBinaryByIdMap.get(objectId);
    }

    /**
     * Returns corresponding PDF object identifier for the extracted revocation token
     *
     * @param ocspToken {@link eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary} to get id for
     * @return a set of {@link Long} identifiers
     */
    protected Set<Long> getRevocationTokenIds(RevocationToken<OCSP> ocspToken) {
        return ocspTokenMap.get(ocspToken);
    }

    @Override
    public void addRevocation(RevocationToken<OCSP> token, EncapsulatedRevocationTokenIdentifier<OCSP> binary) {
        super.addRevocation(token, binary);

        Set<Long> tokenBinaryObjectIds = getTokenBinaryObjectIds(binary);
        ocspTokenMap.put(token, tokenBinaryObjectIds);
    }

    /**
     * Returns PDF object identifier for the provided binary
     *
     * @param binary {@link OCSPResponseBinary}
     * @return a set of {@link Long} identifiers
     */
    protected Set<Long> getTokenBinaryObjectIds(EncapsulatedRevocationTokenIdentifier<OCSP> binary) {
        return ocspBinaryByObjectMap.get(binary);
    }

}
