package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
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
    private final Map<Long, Set<CRLBinary>> crlBinaryByIdMap = new HashMap<>();

    /** Composite map of CRL tokens extracted from different /DSS revisions by encoded object binaries */
    private final Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<Long>> crlBinaryByObjectMap = new HashMap<>();

    /** Cached map of created CRLTokens and corresponding PDF object ids */
    private final Map<RevocationToken<CRL>, Set<Long>> crlTokenMap = new HashMap<>();

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
        Map<Long, CRLBinary> dssCrlMap = dssDictionary.getCRLs();
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
            List<PdfVRIDict> vriDictList = dssDictionary.getVRIs();
            for (PdfVRIDict vriDict : vriDictList) {
                populateObjectsMap(vriDict.getCRLs());
                extractVRICRLs(vriDict);
            }
        }
    }

    private void populateObjectsMap(Map<Long, CRLBinary> crlMap) {
        for (Map.Entry<Long, CRLBinary> entry : crlMap.entrySet()) {
            populateMapById(entry.getKey(), entry.getValue());
            populateMapByObject(entry.getKey(), entry.getValue());
        }
    }

    private void populateMapById(Long objectId, CRLBinary crlBinary) {
        Set<CRLBinary> crlBinaries = crlBinaryByIdMap.get(objectId);
        if (crlBinaries == null) {
            crlBinaries = new HashSet<>();
        }
        crlBinaries.add(crlBinary);
        crlBinaryByIdMap.put(objectId, crlBinaries);
    }

    private void populateMapByObject(Long objectId, CRLBinary crlBinary) {
        Set<Long> objectIds = crlBinaryByObjectMap.get(crlBinary);
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
    protected void extractVRICRLs(PdfVRIDict vriDictionary) {
        if (vriDictionary != null) {
            for (Map.Entry<Long, CRLBinary> crlEntry : vriDictionary.getCRLs().entrySet()) {
                addBinary(crlEntry.getValue(), RevocationOrigin.VRI_DICTIONARY);
            }
        }
    }

    /**
     * This method returns a set of {@code CertificateToken}s with the given PDF object id
     *
     * @param objectId {@link Long} PDF id of the object to be extracted
     * @return set of {@link CRLBinary}s
     */
    protected Set<CRLBinary> getCRLBinariesByObjectId(Long objectId) {
        return crlBinaryByIdMap.get(objectId);
    }

    /**
     * Returns corresponding PDF object identifier for the extracted revocation token
     *
     * @param crlToken {@link eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken} to get id for
     * @return a set of {@link Long} identifiers
     */
    protected Set<Long> getRevocationTokenIds(RevocationToken<CRL> crlToken) {
        return crlTokenMap.get(crlToken);
    }

    @Override
    public void addRevocation(RevocationToken<CRL> token, EncapsulatedRevocationTokenIdentifier<CRL> binary) {
        super.addRevocation(token, binary);

        Set<Long> tokenBinaryObjectIds = getTokenBinaryObjectIds(binary);
        crlTokenMap.put(token, tokenBinaryObjectIds);
    }

    /**
     * Returns PDF object identifier for the provided binary
     *
     * @param binary {@link CRLBinary}
     * @return {@link Long} identifier
     */
    protected Set<Long> getTokenBinaryObjectIds(EncapsulatedRevocationTokenIdentifier<CRL> binary) {
        return crlBinaryByObjectMap.get(binary);
    }

}
