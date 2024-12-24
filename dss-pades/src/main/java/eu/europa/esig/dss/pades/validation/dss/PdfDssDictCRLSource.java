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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PdfObjectKey;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfVriDict;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
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
 * The CRL source extracted from a DSS dictionary
 */
@SuppressWarnings("serial")
public class PdfDssDictCRLSource extends OfflineCRLSource {

    private static final long serialVersionUID = 7920126699012690199L;

    /** Merged certificate source combined from all /DSS revisions */
    private final PdfCompositeDssDictCRLSource compositeCRLSource;

    /** The DSS dictionary */
    private final PdfDssDict dssDictionary;

    /** Name of the signature's VRI dictionary, when applicable */
    private final String relatedVRIDictionaryName;

    /** Cached CRL Map */
    private Map<PdfObjectKey, CRLBinary> crlMap;

    /**
     * Default constructor
     *
     * @param compositeCRLSource {@link PdfCompositeDssDictCRLSource}
     * @param dssDictionary {@link PdfDssDict}
     */
    public PdfDssDictCRLSource(final PdfCompositeDssDictCRLSource compositeCRLSource,
                               final PdfDssDict dssDictionary)  {
        this(compositeCRLSource, dssDictionary, null);
    }

    /**
     * Constructor with VRI dictionary name, to be used for a signature source
     *
     * @param compositeCRLSource {@link PdfCompositeDssDictCRLSource}
     * @param dssDictionary {@link PdfDssDict}
     * @param vriDictionaryName {@link String} SHA-1 of the signature name
     */
    public PdfDssDictCRLSource(final PdfCompositeDssDictCRLSource compositeCRLSource,
                                final PdfDssDict dssDictionary, final String vriDictionaryName) {
        this.compositeCRLSource = compositeCRLSource;
        this.dssDictionary = dssDictionary;
        this.relatedVRIDictionaryName = vriDictionaryName;
    }

    /**
     * Returns a map of all CRL entries contained in DSS dictionary or into nested
     * VRI dictionaries
     *
     * @return a map of CRL binaries with their object ids
     */
    public Map<PdfObjectKey, CRLBinary> getCrlMap() {
        if (crlMap == null) {
            crlMap = new HashMap<>();
            if (dssDictionary != null) {
                crlMap.putAll(dssDictionary.getCRLs());
                List<PdfVriDict> vriDicts = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
                for (PdfVriDict vriDict : vriDicts) {
                    crlMap.putAll(vriDict.getCRLs());
                }
            }
        }
        return crlMap;
    }

    @Override
    public List<RevocationToken<CRL>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerToken) {
        List<RevocationToken<CRL>> revocationTokens = compositeCRLSource.getRevocationTokens(certificateToken, issuerToken);
        revocationTokens = filterTokensFromCrlMap(revocationTokens);
        revocationTokens.addAll(super.getRevocationTokens(certificateToken, issuerToken));
        return revocationTokens;
    }

    @Override
    public List<EncapsulatedRevocationTokenIdentifier<CRL>> getDSSDictionaryBinaries() {
        if (dssDictionary != null) {
            return filterBinariesFromKeys(compositeCRLSource.getDSSDictionaryBinaries(), dssDictionary.getCRLs().keySet());
        }
        return Collections.emptyList();
    }

    @Override
    public List<RevocationToken<CRL>> getDSSDictionaryTokens() {
        if (dssDictionary != null) {
            return filterTokensFromKeys(compositeCRLSource.getDSSDictionaryTokens(), dssDictionary.getCRLs().keySet());
        }
        return Collections.emptyList();
    }

    @Override
    public List<EncapsulatedRevocationTokenIdentifier<CRL>> getVRIDictionaryBinaries() {
        if (dssDictionary != null) {
            return filterBinariesFromKeys(compositeCRLSource.getVRIDictionaryBinaries(), getKeySetFromVRIDictionaries());
        }
        return Collections.emptyList();
    }

    @Override
    public List<RevocationToken<CRL>> getVRIDictionaryTokens() {
        if (dssDictionary != null) {
            return filterTokensFromKeys(compositeCRLSource.getVRIDictionaryTokens(), getKeySetFromVRIDictionaries());
        }
        return Collections.emptyList();
    }

    private Set<PdfObjectKey> getKeySetFromVRIDictionaries() {
        if (dssDictionary != null) {
            Set<PdfObjectKey> result = new HashSet<>();
            List<PdfVriDict> vris = PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName);
            for (PdfVriDict vriDict : vris) {
                result.addAll(vriDict.getCRLs().keySet());
            }
            return result;
        }
        return Collections.emptySet();
    }

    private List<EncapsulatedRevocationTokenIdentifier<CRL>> filterBinariesFromKeys(
            Collection<EncapsulatedRevocationTokenIdentifier<CRL>> crlBinaries, Collection<PdfObjectKey> keySet) {
        List<EncapsulatedRevocationTokenIdentifier<CRL>> result = new ArrayList<>();
        for (EncapsulatedRevocationTokenIdentifier<CRL> crlBinary : crlBinaries) {
            Set<PdfObjectKey> objectIds = compositeCRLSource.getTokenBinaryObjectIds(crlBinary);
            if (Utils.containsAny(keySet, objectIds)) {
                result.add(crlBinary);
            }
        }
        return result;
    }

    private List<RevocationToken<CRL>> filterTokensFromCrlMap(List<RevocationToken<CRL>> revocationTokens) {
        return filterTokensFromKeys(revocationTokens, getCrlMap().keySet());
    }

    private List<RevocationToken<CRL>> filterTokensFromKeys(Collection<RevocationToken<CRL>> revocationTokens, Collection<PdfObjectKey> keySet) {
        List<RevocationToken<CRL>> result = new ArrayList<>();
        for (RevocationToken<CRL> crlToken : revocationTokens) {
            Set<PdfObjectKey> objectIds = compositeCRLSource.getRevocationTokenIds(crlToken);
            if (Utils.containsAny(keySet, objectIds)) {
                result.add(crlToken);
            }
        }
        return result;
    }

    @Override
    public Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> getAllRevocationBinariesWithOrigins() {
        Map<EncapsulatedRevocationTokenIdentifier<CRL>, Set<RevocationOrigin>> result = new HashMap<>();

        Set<EncapsulatedRevocationTokenIdentifier<CRL>> binaries = compositeCRLSource.getAllRevocationBinaries();
        List<EncapsulatedRevocationTokenIdentifier<CRL>> filteredBinaries = filterBinariesFromKeys(binaries, getCrlMap().keySet());
        for (EncapsulatedRevocationTokenIdentifier<CRL> CRLBinary : filteredBinaries) {
            result.put(CRLBinary, getRevocationDataOrigins(CRLBinary));
        }
        return result;
    }

    private Set<RevocationOrigin> getRevocationDataOrigins(EncapsulatedRevocationTokenIdentifier<CRL> crlBinary) {
        Set<RevocationOrigin> result = new HashSet<>();
        Set<PdfObjectKey> tokenBinaryObjectIds = compositeCRLSource.getTokenBinaryObjectIds(crlBinary);
        if (Utils.containsAny(dssDictionary.getCRLs().keySet(), tokenBinaryObjectIds)) {
            result.add(RevocationOrigin.DSS_DICTIONARY);
        }
        for (PdfVriDict vriDict : PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName)) {
            if (Utils.containsAny(vriDict.getCRLs().keySet(), tokenBinaryObjectIds)) {
                result.add(RevocationOrigin.VRI_DICTIONARY);
            }
        }
        return result;
    }

    @Override
    public Map<RevocationToken<CRL>, Set<RevocationOrigin>> getAllRevocationTokensWithOrigins() {
        Map<RevocationToken<CRL>, Set<RevocationOrigin>> result = new HashMap<>();

        Set<RevocationToken<CRL>> tokens = compositeCRLSource.getAllRevocationTokens();
        List<RevocationToken<CRL>> filteredBinaries = filterTokensFromKeys(tokens, getCrlMap().keySet());
        for (RevocationToken<CRL> CRLToken : filteredBinaries) {
            result.put(CRLToken, getRevocationDataOrigins(CRLToken));
        }
        return result;
    }

    private Set<RevocationOrigin> getRevocationDataOrigins(RevocationToken<CRL> crlToken) {
        Set<RevocationOrigin> result = new HashSet<>();
        Set<PdfObjectKey> tokenObjectIds = compositeCRLSource.getRevocationTokenIds(crlToken);
        if (Utils.containsAny(dssDictionary.getCRLs().keySet(), tokenObjectIds)) {
            result.add(RevocationOrigin.DSS_DICTIONARY);
        }
        for (PdfVriDict vriDict : PAdESUtils.getVRIsWithName(dssDictionary, relatedVRIDictionaryName)) {
            if (Utils.containsAny(vriDict.getCRLs().keySet(), tokenObjectIds)) {
                result.add(RevocationOrigin.VRI_DICTIONARY);
            }
        }
        return result;
    }

}
