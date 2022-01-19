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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVRIDict;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The OCSP source extracted from a DSS dictionary
 */
@SuppressWarnings("serial")
public class PdfDssDictOCSPSource extends OfflineOCSPSource {

    private static final long serialVersionUID = 1503525374769179608L;

    /** Merged certificate source combined from all /DSS revisions */
    private final PdfCompositeDssDictOCSPSource compositeOCSPSource;

    /** The DSS dictionary */
    private final PdfDssDict dssDictionary;

    /** Name of the signature's VRI dictionary, when applicable */
    private final String relatedVRIDictionaryName;

    /** Cached OCSP Map */
    private Map<Long, OCSPResponseBinary> ocspMap;

    /**
     * Default constructor
     *
     * @param compositeOCSPSource {@link PdfCompositeDssDictOCSPSource}
     * @param dssDictionary {@link PdfDssDict}
     */
    public PdfDssDictOCSPSource(final PdfCompositeDssDictOCSPSource compositeOCSPSource,
                               final PdfDssDict dssDictionary) {
        this(compositeOCSPSource, dssDictionary, null);
    }

    /**
     * Constructor with VRI dictionary name, to be used for a signature source
     *
     * @param compositeOCSPSource {@link PdfCompositeDssDictOCSPSource}
     * @param dssDictionary {@link PdfDssDict}
     * @param vriDictionaryName {@link String} SHA-1 of the signature name
     */
    public PdfDssDictOCSPSource(final PdfCompositeDssDictOCSPSource compositeOCSPSource,
                                final PdfDssDict dssDictionary, final String vriDictionaryName) {
        this.compositeOCSPSource = compositeOCSPSource;
        this.dssDictionary = dssDictionary;
        this.relatedVRIDictionaryName = vriDictionaryName;
    }

    /**
     * Returns a map of all OCSP entries contained in DSS dictionary or into nested
     * VRI dictionaries
     *
     * @return a map of OCSP binaries with their object ids
     */
    public Map<Long, OCSPResponseBinary> getOcspMap() {
        if (ocspMap == null) {
            ocspMap = new HashMap<>();
            if (dssDictionary != null) {
                ocspMap.putAll(dssDictionary.getOCSPs());
                List<PdfVRIDict> vriDicts = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
                for (PdfVRIDict vriDict : vriDicts) {
                    ocspMap.putAll(vriDict.getOCSPs());
                }
            }
        }
        return ocspMap;
    }

    @Override
    public List<RevocationToken<OCSP>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerToken) {
        List<RevocationToken<OCSP>> revocationTokens = compositeOCSPSource.getRevocationTokens(certificateToken, issuerToken);
        return filterTokensFromOcspMap(revocationTokens);
    }

    @Override
    public List<EncapsulatedRevocationTokenIdentifier<OCSP>> getDSSDictionaryBinaries() {
        if (dssDictionary != null) {
            return filterBinariesFromKeys(compositeOCSPSource.getDSSDictionaryBinaries(), dssDictionary.getOCSPs().keySet());
        }
        return Collections.emptyList();
    }

    @Override
    public List<RevocationToken<OCSP>> getDSSDictionaryTokens() {
        if (dssDictionary != null) {
            return filterTokensFromKeys(compositeOCSPSource.getDSSDictionaryTokens(), dssDictionary.getOCSPs().keySet());
        }
        return Collections.emptyList();
    }

    @Override
    public List<EncapsulatedRevocationTokenIdentifier<OCSP>> getVRIDictionaryBinaries() {
        if (dssDictionary != null) {
            return filterBinariesFromKeys(compositeOCSPSource.getVRIDictionaryBinaries(), getKeySetFromVRIDictionaries());
        }
        return Collections.emptyList();
    }

    @Override
    public List<RevocationToken<OCSP>> getVRIDictionaryTokens() {
        if (dssDictionary != null) {
            return filterTokensFromKeys(compositeOCSPSource.getVRIDictionaryTokens(), getKeySetFromVRIDictionaries());
        }
        return Collections.emptyList();
    }

    private Set<Long> getKeySetFromVRIDictionaries() {
        if (dssDictionary != null) {
            Set<Long> result = new HashSet<>();
            List<PdfVRIDict> vris = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
            for (PdfVRIDict vriDict : vris) {
                result.addAll(vriDict.getOCSPs().keySet());
            }
            return result;
        }
        return Collections.emptySet();
    }

    private List<EncapsulatedRevocationTokenIdentifier<OCSP>> filterBinariesFromKeys(
            Collection<EncapsulatedRevocationTokenIdentifier<OCSP>> OCSPBinaries, Collection<Long> keySet) {
        List<EncapsulatedRevocationTokenIdentifier<OCSP>> result = new ArrayList<>();
        for (EncapsulatedRevocationTokenIdentifier<OCSP> OCSPBinary : OCSPBinaries) {
            Set<Long> objectIds = compositeOCSPSource.getTokenBinaryObjectIds(OCSPBinary);
            if (Utils.containsAny(keySet, objectIds)) {
                result.add(OCSPBinary);
            }
        }
        return result;
    }

    private List<RevocationToken<OCSP>> filterTokensFromOcspMap(List<RevocationToken<OCSP>> revocationTokens) {
        return filterTokensFromKeys(revocationTokens, getOcspMap().keySet());
    }

    private List<RevocationToken<OCSP>> filterTokensFromKeys(Collection<RevocationToken<OCSP>> revocationTokens, Collection<Long> keySet) {
        List<RevocationToken<OCSP>> result = new ArrayList<>();
        for (RevocationToken<OCSP> OCSPToken : revocationTokens) {
            Set<Long> objectIds = compositeOCSPSource.getRevocationTokenIds(OCSPToken);
            if (Utils.containsAny(keySet, objectIds)) {
                result.add(OCSPToken);
            }
        }
        return result;
    }

    @Override
    public Map<EncapsulatedRevocationTokenIdentifier<OCSP>, Set<RevocationOrigin>> getAllRevocationBinariesWithOrigins() {
        Map<EncapsulatedRevocationTokenIdentifier<OCSP>, Set<RevocationOrigin>> result = new HashMap<>();

        Set<EncapsulatedRevocationTokenIdentifier<OCSP>> binaries = compositeOCSPSource.getAllRevocationBinaries();
        List<EncapsulatedRevocationTokenIdentifier<OCSP>> filteredBinaries = filterBinariesFromKeys(binaries, getOcspMap().keySet());
        for (EncapsulatedRevocationTokenIdentifier<OCSP> ocspBinary : filteredBinaries) {
            result.put(ocspBinary, getRevocationDataOrigins(ocspBinary));
        }
        return result;
    }

    private Set<RevocationOrigin> getRevocationDataOrigins(EncapsulatedRevocationTokenIdentifier<OCSP> ocspBinary) {
        Set<RevocationOrigin> result = new HashSet<>();
        Set<Long> tokenBinaryObjectIds = compositeOCSPSource.getTokenBinaryObjectIds(ocspBinary);
        if (Utils.containsAny(dssDictionary.getOCSPs().keySet(), tokenBinaryObjectIds)) {
            result.add(RevocationOrigin.DSS_DICTIONARY);
        }
        for (PdfVRIDict vriDict : PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName)) {
            if (Utils.containsAny(vriDict.getOCSPs().keySet(), tokenBinaryObjectIds)) {
                result.add(RevocationOrigin.VRI_DICTIONARY);
            }
        }
        return result;
    }

    @Override
    public Map<RevocationToken<OCSP>, Set<RevocationOrigin>> getAllRevocationTokensWithOrigins() {
        Map<RevocationToken<OCSP>, Set<RevocationOrigin>> result = new HashMap<>();

        Set<RevocationToken<OCSP>> tokens = compositeOCSPSource.getAllRevocationTokens();
        List<RevocationToken<OCSP>> filteredBinaries = filterTokensFromKeys(tokens, getOcspMap().keySet());
        for (RevocationToken<OCSP> ocspToken : filteredBinaries) {
            result.put(ocspToken, getRevocationDataOrigins(ocspToken));
        }
        return result;
    }

    private Set<RevocationOrigin> getRevocationDataOrigins(RevocationToken<OCSP> ocspToken) {
        Set<RevocationOrigin> result = new HashSet<>();
        Set<Long> tokenObjectIds = compositeOCSPSource.getRevocationTokenIds(ocspToken);
        if (Utils.containsAny(dssDictionary.getOCSPs().keySet(), tokenObjectIds)) {
            result.add(RevocationOrigin.DSS_DICTIONARY);
        }
        for (PdfVRIDict vriDict : PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName)) {
            if (Utils.containsAny(vriDict.getOCSPs().keySet(), tokenObjectIds)) {
                result.add(RevocationOrigin.VRI_DICTIONARY);
            }
        }
        return result;
    }

}
