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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationSDPayloadBuilder;
import eu.europa.esig.dss.attestation.common.creation.TokenStatusList;
import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.attestation.mdoc.key.COSEKeyBuilder;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class provides access to a configuration to build a payload for an ISO/IEC 18013-5 mdoc attestation.
 *
 */
public class MdocPayloadBuilder extends AbstractAttestationSDPayloadBuilder<MdocPayloadParameters, MdocIssuerSignedItem> {

    private static final Logger LOG = LoggerFactory.getLogger(MdocPayloadBuilder.class);

    /**
     * Builds disclosures
     */
    private MdocSelectiveDisclosureBuilder disclosureBuilder = new DefaultMdocSelectiveDisclosureBuilder();

    /**
     * Provides MdocClaimsBuilder to build claims
     */
    private MdocClaimsBuilderFactory mdocClaimsBuilderFactory;

    /**
     * Empty constructor
     */
    public MdocPayloadBuilder() {
        // empty
    }

    /**
     * Sets a disclosure builder.
     * Default : {@code eu.europa.esig.dss.attestation.mdoc.creation.DefaultMdocDisclosureBuilder}
     *
     * @param disclosureBuilder {@link MdocSelectiveDisclosureBuilder}
     */
    public void setDisclosureBuilder(MdocSelectiveDisclosureBuilder disclosureBuilder) {
        Objects.requireNonNull(disclosureBuilder, "Disclosure builder cannot be null!");
        this.disclosureBuilder = disclosureBuilder;
    }

    /**
     * Gets the MdocClaimsBuilderFactory
     * Default : {@code DefaultMdocClaimsBuilderFactory}
     *
     * @return {@link MdocClaimsBuilderFactory}
     */
    protected MdocClaimsBuilderFactory getMdocClaimProviderFactory() {
        if (mdocClaimsBuilderFactory == null) {
            mdocClaimsBuilderFactory = new DefaultMdocClaimsBuilderFactory();
        }
        return mdocClaimsBuilderFactory;
    }

    /**
     * Sets MdocClaimsBuilderFactory, providing definition of the claims for the given document type.
     * Default : {@code DefaultMdocClaimsBuilderFactory}. Supported docType's are:
     *           "org.iso.18013.5.1.mDL", "org.iso.23220.1.mID", "eu.europa.ec.eudi.pid.1".
     *           For other types it is recommended to provide a custom implementation.
     *
     * @param mdocClaimsBuilderFactory {@link MdocClaimsBuilderFactory}
     */
    public void setMdocClaimProviderFactory(MdocClaimsBuilderFactory mdocClaimsBuilderFactory) {
        this.mdocClaimsBuilderFactory = mdocClaimsBuilderFactory;
    }

    @Override
    public DSSDocument buildPayload(MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "MdocPayloadParameters cannot be null!");
        CBORValue mso = buildMobileSecurityObject(payloadParameters);
        CBORValue msoBytes = CBORTags.encodedCbor(mso.encodeToBytes());
        return new InMemoryDocument(CBORUtils.serializeCbor(msoBytes));
    }

    /**
     * Builds a Mobile Security Object (MSO) as defined in "9.1.2.4 Signing method and structure for MSO"
     * {@code
     *   MobileSecurityObject = {
     *     "version" : tstr,                       ; Version of the MobileSecurityObject
     *     "digestAlgorithm" : tstr,               ; Message digest algorithm used
     *     "valueDigests" : ValueDigests,          ; Digests of all data elements per namespace
     *     "deviceKeyInfo" : DeviceKeyInfo,
     *     "docType" : tstr,                       ; docType as used in Documents
     *     "validityInfo" : ValidityInfo
     *   }
     * }
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link CBORValue}
     */
    protected CBORValue buildMobileSecurityObject(MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters.getVersion(), "Version cannot be null!");
        Objects.requireNonNull(payloadParameters.getDigestAlgorithm(), "DigestAlgorithm cannot be null!");
        Objects.requireNonNull(payloadParameters.getDocType(), "DocType cannot be null!");

        CBORValue.CBORMapEditor mso = CBOR.map()
                .put(MdocConstants.VERSION, payloadParameters.getVersion())
                .put(MdocConstants.DIGEST_ALGORITHM, payloadParameters.getDigestAlgorithm().getMSOId())
                .put(MdocConstants.VALUE_DIGEST, buildValueDigests(payloadParameters))
                .put(MdocConstants.DEVICE_KEY_INFO, buildDeviceKeyInfo(payloadParameters))
                .put(MdocConstants.DOC_TYPE, payloadParameters.getDocType())
                .put(MdocConstants.VALIDITY_INFO, buildValidityInfo(payloadParameters));
        CBORValue status = buildStatus(payloadParameters.getIdentifierList(), payloadParameters.getStatusList());
        if (status != null) {
            mso.put(MdocConstants.STATUS, status);
        }
        return mso.value();
    }

    /**
     * Builds a ValueDigests based on the set claims.
     * {@code
     *   ValueDigests = {
     *     + NameSpace => DigestIDs
     *   }
     * }
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link CBORValue}
     */
    protected CBORValue buildValueDigests(MdocPayloadParameters payloadParameters) {
        final CBORValue.CBORMapEditor valueDigests = CBOR.map();
        SecureRandom secureRandom = secureRandom(payloadParameters);
        for (Map.Entry<String, List<MdocClaim>> claimsEntry : getRootPayloadClaims(payloadParameters).entrySet()) {
            String namespace = claimsEntry.getKey();
            List<MdocClaim> claims = claimsEntry.getValue();
            valueDigests.put(namespace, buildDigestIDs(claims, payloadParameters, secureRandom));
        }
        return valueDigests.value();
    }

    /**
     * Builds a map of elements for each namespace
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return a map between namespaces and corresponding list of claims
     */
    protected Map<String, List<MdocClaim>> getRootPayloadClaims(MdocPayloadParameters payloadParameters) {
        MdocClaimsBuilder mdocClaimsBuilder = getMdocClaimProviderFactory().create(payloadParameters);
        List<MdocClaim> claims = mdocClaimsBuilder.buildClaims(payloadParameters);
        if (Utils.isCollectionEmpty(claims)) {
            throw new IllegalArgumentException("No selectively disclosable claims were defined! " +
                    "Please provide at least one for a compliant mdoc creation.");
        }
        return claims.stream().collect(Collectors.groupingBy(
                MdocClaim::getNamespace, LinkedHashMap::new, Collectors.toList()));
    }

    /**
     * Gets the claims, including the decoy values and/randomized, when applicable
     *
     * @param claims a list of {@link MdocClaim}s
     * @param payloadParameters {@link MdocPayloadParameters}
     * @param secureRandom {@link SecureRandom} to generate salt
     * @return a list of {@link Digest}s
     */
    protected List<MdocClaim> randomize(List<MdocClaim> claims, MdocPayloadParameters payloadParameters, SecureRandom secureRandom) {
        claims = new ArrayList<>(claims);
        for (int i = 0; i < payloadParameters.getDecoyDigestNumber(); i++) {
            byte[] bytes = nextRandomSalt(secureRandom);
            claims.add(MdocClaim.create(bytes));
        }
        if (payloadParameters.isShuffleHashes()) {
            Collections.shuffle(claims, secureRandom);
        }
        return claims;
    }

    /**
     * Builds a DigestIDs structure.
     * {@code
     *   DigestIDs = {
     *     + DigestID => Digest
     *   }
     * }
     *
     * @param claims a list of {@link MdocClaim}s
     * @param payloadParameters {@link MdocPayloadParameters}
     * @param secureRandom {@link SecureRandom}
     * @return {@link CBORValue}
     */
    protected CBORValue buildDigestIDs(List<MdocClaim> claims, MdocPayloadParameters payloadParameters, SecureRandom secureRandom) {
        if (Utils.isCollectionEmpty(claims)) {
            throw new IllegalStateException("The list of claims is empty!");
        }

        final CBORValue.CBORMapEditor digestIDs = CBOR.map();
        List<MdocIssuerSignedItem> disclosures = buildDisclosures(claims, payloadParameters, secureRandom, true);
        disclosures.forEach(d -> {
            Digest digest = d.getDigest(payloadParameters.getDigestAlgorithm());
            digestIDs.put(d.getDigestId(), digest.getValue());
        });
        return digestIDs.value();
    }

    /**
     * Builds a DeviceKeyInfo structure.
     * {@code
     *   DeviceKeyInfo = {
     *     "deviceKey" : DeviceKey
     *     ? "keyAuthorizations" : KeyAuthorizations,
     *     ? "keyInfo" : KeyInfo
     *   }
     *   DeviceKey = COSE_Key
     * }
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link CBORValue}
     */
    protected CBORValue buildDeviceKeyInfo(MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters.getDeviceKey(), "DeviceKey shall be provided for an mdoc payload building!");
        final CBORValue.CBORMapEditor deviceKeyInfo = CBOR.map();
        deviceKeyInfo.put(MdocConstants.DEVICE_KEY, buildCOSEKey(payloadParameters.getDeviceKey()));
        CBORValue keyAuthorizations = buildKeyAuthorizations(payloadParameters.getKeyAuthorizationsNamespaces(), payloadParameters.getKeyAuthorizationsDataElements());
        if (keyAuthorizations != null && keyAuthorizations.size() != 0) {
            deviceKeyInfo.put(MdocConstants.KEY_AUTHORIZATIONS, keyAuthorizations);
        }
        CBORValue keyInfo = buildKeyInfo(payloadParameters.getKeyInfoMap());
        if (keyInfo != null && keyInfo.size() != 0) {
            deviceKeyInfo.put(MdocConstants.KEY_INFO, keyInfo);
        }
        return deviceKeyInfo.value();
    }

    /**
     * Builds a COSE_Key representation of a device's {@code PublicKey}
     *
     * @param publicKey {@link PublicKey}
     * @return {@link CBORValue}
     */
    protected CBORValue buildCOSEKey(PublicKey publicKey) {
        PublicKeyInfo publicKeyInfo = getPublicKeyInfoFactory().create(publicKey);
        return new COSEKeyBuilder(publicKeyInfo).create();
    }

    /**
     * Builds a KeyAuthorizations structure.
     * {@code
     *   KeyAuthorizations = {
     *     ? "nameSpaces" : AuthorizedNameSpaces
     *     ? "dataElements" : AuthorizedDataElements
     *   }
     *   AuthorizedNameSpaces = [+ NameSpace]
     *   AuthorizedDataElements = {+ NameSpace => DataElementsArray}
     *   DataElementsArray = [+ DataElementIdentifier]
     * }
     *
     * @param keyAuthorizationsNamespaces a list of {@link String}s
     * @param keyAuthorizationsDataElements a map of {@link String} namespaces and corresponding {@link String} data elements
     * @return {@link CBORValue}
     */
    protected CBORValue buildKeyAuthorizations(List<String> keyAuthorizationsNamespaces, Map<String, List<String>> keyAuthorizationsDataElements) {
        if (Utils.isCollectionEmpty(keyAuthorizationsNamespaces) && Utils.isMapEmpty(keyAuthorizationsDataElements)) {
            return null;
        }
        final CBORValue.CBORMapEditor keyAuthorizations = CBOR.map();
        if (Utils.isCollectionNotEmpty(keyAuthorizationsNamespaces)) {
            keyAuthorizations.put(MdocConstants.NAMESPACES, CBOR.array(keyAuthorizationsNamespaces).value());
        }
        if (Utils.isMapNotEmpty(keyAuthorizationsDataElements)) {
            CBORValue.CBORMapEditor authorizedDataElements = CBOR.map();
            keyAuthorizationsDataElements.forEach((k, v) -> authorizedDataElements.put(k, CBOR.array(v).value()));
            keyAuthorizations.put(MdocConstants.DATA_ELEMENTS, authorizedDataElements.value());
        }
        return keyAuthorizations.value();
    }

    /**
     * Builds a KeyInfo structure.
     * {@code
     *   KeyInfo = { * int => any}   ; Positive integers are RFU, negative integers may be used for
     *   proprietary use
     * }
     *
     * @param keyInfoMap the keyInfo map
     * @return {@link CBORValue}
     */
    protected CBORValue buildKeyInfo(Map<Integer, Object> keyInfoMap) {
        if (Utils.isMapEmpty(keyInfoMap)) {
            return null;
        }
        final CBORValue.CBORMapEditor keyInfo = CBOR.map();
        keyInfoMap.forEach(keyInfo::put);
        return keyInfo.value();
    }

    /**
     * Builds a ValidityInfo structure.
     * {@code
     *   ValidityInfo = {
     *     "signed" : tdate,
     *     "validFrom" : tdate,
     *     "validUntil" : tdate,
     *     ? "expectedUpdate" : tdate
     *   }
     * }
     *
     * @param payloadParameters {@link MdocPayloadParameters}
     * @return {@link CBORValue}
     */
    protected CBORValue buildValidityInfo(MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters.getSigned(), "signed date cannot be null!");
        Objects.requireNonNull(payloadParameters.getValidFrom(), "validFrom date cannot be null!");
        Objects.requireNonNull(payloadParameters.getValidUntil(), "validUntil date cannot be null!");

        final CBORValue.CBORMapEditor validityInfo = CBOR.map();
        validityInfo.put(MdocConstants.SIGNED, CBORTags.tdate(payloadParameters.getSigned()));
        validityInfo.put(MdocConstants.VALID_FROM, CBORTags.tdate(payloadParameters.getValidFrom()));
        validityInfo.put(MdocConstants.VALID_UNTIL, CBORTags.tdate(payloadParameters.getValidUntil()));
        if (payloadParameters.getExpectedUpdate() != null) {
            validityInfo.put(MdocConstants.EXPECTED_UPDATE, CBORTags.tdate(payloadParameters.getExpectedUpdate()));
        }
        return validityInfo.value();
    }

    /**
     * Builds a Status structure.
     * NOTE: The "status" is not defined in ISO/IEC 18013-5:2021,
     * but referenced in the draft of the amendments to the EU Implementing Acts.
     * {@code
     *   Status = {
     *     ? "identifier_list”: IdentifierListInfo,
     *     ? "status_list”: StatusListInfo,
     *     * tstr => RFU
     *   }
     * }
     *
     * @param identifierList {@link MdocIdentifierList}
     * @param statusList {@link TokenStatusList}
     * @return {@link CBORValue}
     */
    protected CBORValue buildStatus(MdocIdentifierList identifierList, TokenStatusList statusList) {
        if (identifierList == null && statusList == null) {
            return null;
        }
        final CBORValue.CBORMapEditor status = CBOR.map();
        CBORValue identifierListInfo = buildIdentifierListInfo(identifierList);
        if (identifierListInfo != null) {
            status.put(MdocConstants.IDENTIFIER_LIST, identifierListInfo);
        }
        CBORValue statusListInfo = buildStatusListInfo(statusList);
        if (statusListInfo != null) {
            status.put(MdocConstants.STATUS_LIST, statusListInfo);
        }
        return status.value();
    }

    /**
     * Builds an IdentifierListInfo  structure.
     * {@code
     *   IdentifierListInfo = {
     *     "id": Identifier ,
     *     "uri": URI,
     *     ? "certificate": Certificate
     *     * tstr => RFU
     *   }
     *   Identifier = bstr
     *   URI = tstr
     *   Certificate = bstr
     * }
     *
     * @param identifierList {@link MdocIdentifierList}
     * @return {@link CBORValue}
     */
    protected CBORValue buildIdentifierListInfo(MdocIdentifierList identifierList) {
        if (identifierList == null) {
            return null;
        }
        final CBORValue.CBORMapEditor identifierListInfo = CBOR.map();
        identifierListInfo.put(MdocConstants.IDENTIFIER_ID, identifierList.getIdentifier());
        identifierListInfo.put(MdocConstants.IDENTIFIER_URI, identifierList.getUri());
        if (identifierList.getCertificate() != null) {
            identifierListInfo.put(MdocConstants.IDENTIFIER_CERTIFICATE, identifierList.getCertificate().getEncoded());
        }
        return identifierListInfo.value();
    }

    /**
     * Builds an StatusListInfo structure.
     * {@code
     *   StatusListInfo = {
     *     "idx": unit,
     *     "uri": tstr,
     *     ? "certificate": bstr
     *   }
     * }
     *
     * @param statusList {@link TokenStatusList}
     * @return {@link CBORValue}
     */
    protected CBORValue buildStatusListInfo(TokenStatusList statusList) {
        if (statusList == null) {
            return null;
        }
        final CBORValue.CBORMapEditor statusListInfo = CBOR.map();
        statusListInfo.put(MdocConstants.STATUS_IDX, statusList.getIndex());
        statusListInfo.put(MdocConstants.STATUS_URI, statusList.getUri());
        if (statusList.getCertificate() != null) {
            statusListInfo.put(MdocConstants.STATUS_CERTIFICATE, statusList.getCertificate().getEncoded());
        }
        return statusListInfo.value();
    }

    @Override
    public List<MdocIssuerSignedItem> buildDisclosures(MdocPayloadParameters payloadParameters) {
        Objects.requireNonNull(payloadParameters, "Payload parameters cannot be null!");
        Objects.requireNonNull(payloadParameters.getDigestAlgorithm(), "Digest algorithm cannot be null!");

        final List<MdocIssuerSignedItem> result = new ArrayList<>();
        SecureRandom secureRandom = secureRandom(payloadParameters);
        getRootPayloadClaims(payloadParameters).values().forEach(c -> result.addAll(buildDisclosures(c, payloadParameters, secureRandom, false)));
        return result;
    }

    /**
     * Builds disclosures for the given list of {@code claims} using the provided {@code secureRandom}
     *
     * @param claims a list of {@link MdocClaim}s to build disclosures for
     * @param payloadParameters {@link MdocPayloadParameters}
     * @param secureRandom {@link SecureRandom} to be used for salt generation, where applicable
     * @param includeVoid whether the void claims are to be included in the final result
     * @return a list of {@link MdocIssuerSignedItem}s
     */
    protected List<MdocIssuerSignedItem> buildDisclosures(List<MdocClaim> claims, MdocPayloadParameters payloadParameters,
                                                          SecureRandom secureRandom, boolean includeVoid) {
        if (Utils.isCollectionEmpty(claims)) {
            throw new IllegalStateException("The list of claims is empty!");
        }
        claims = randomize(claims, payloadParameters, secureRandom);

        final List<MdocIssuerSignedItem> result = new ArrayList<>();

        for (int i = 0; i < claims.size(); i++) {
            MdocClaim claim = claims.get(i);
            ensureDigestId(claim, i + 1, claims);
            ensureSalt(claim, secureRandom);
            if (claim.isVoid() && !includeVoid) {
                continue;
            }

            result.add(disclosureBuilder.build(claim));
        }
        return result;
    }

    /**
     * This method ensures the digestId value within the claim for a disclosure building, if not defined
     *
     * @param claim {@link MdocClaim}
     * @param index current index of the claim in the list
     * @param claims a list of all {@link MdocClaim}s within the current namespace
     */
    protected void ensureDigestId(MdocClaim claim, int index, List<MdocClaim> claims) {
        if (claim.getDigestId() == null) {
            while (isDigestIdUsed(index, claims)) {
                ++index;
            }
            claim.setDigestId(index);
            if (LOG.isTraceEnabled()) {
                LOG.trace("DigestId has been added for a claim");
            }
        }
    }

    private boolean isDigestIdUsed(int digestId, List<MdocClaim> claims) {
        return claims.stream().anyMatch(c -> c.getDigestId() != null && digestId == c.getDigestId());
    }

    /**
     * This method ensures the salt value within the claim for a disclosure building, if not defined.
     * This method uses a {@code secureRandomProvider} for the deterministic salt generation
     *
     * @param claim {@link MdocClaim}
     * @param secureRandom {@link SecureRandom}
     */
    protected void ensureSalt(MdocClaim claim, SecureRandom secureRandom) {
        if (claim.getSalt() == null) {
            claim.setSalt(nextRandomSalt(secureRandom));
            if (LOG.isTraceEnabled()) {
                LOG.trace("Salt has been added for a claim");
            }
        }
    }

}
