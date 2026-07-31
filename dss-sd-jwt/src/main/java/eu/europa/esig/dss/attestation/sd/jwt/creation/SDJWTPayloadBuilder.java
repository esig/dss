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
package eu.europa.esig.dss.attestation.sd.jwt.creation;

import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationSDPayloadBuilder;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Creates a payload for an RFC 9901 SD-JWT token based on the provided parameters
 *
 */
public class SDJWTPayloadBuilder extends AbstractAttestationSDPayloadBuilder<SDJWTPayloadParameters, SDJWTSelectiveDisclosure> {

    /** Builds disclosures */
    private SDJWTSelectiveDisclosureBuilder disclosureBuilder = new DefaultSDJWTSelectiveDisclosureBuilder();

    /** Builds known and custom claims */
    private SDJWTClaimBuilder claimBuilder = new DefaultSDJWTClaimBuilder();

    /**
     * Default constructor
     */
    public SDJWTPayloadBuilder() {
        // empty
    }

    /**
     * Sets a disclosure builder.
     * Default : {@code eu.europa.esig.dss.attestation.sd.jwt.creation.DefaultSDJWTDisclosureBuilder}
     *
     * @param disclosureBuilder {@link SDJWTSelectiveDisclosureBuilder}
     */
    public void setDisclosureBuilder(SDJWTSelectiveDisclosureBuilder disclosureBuilder) {
        Objects.requireNonNull(disclosureBuilder, "Disclosure builder cannot be null!");
        this.disclosureBuilder = disclosureBuilder;
    }

    /**
     * Gets a configured instance of {@code SDJWTClaimBuilder}
     *
     * @return {@link SDJWTClaimBuilder}
     */
    protected SDJWTClaimBuilder getClaimBuilder() {
        claimBuilder.setPublicKeyInfoFactory(getPublicKeyInfoFactory());
        return claimBuilder;
    }

    /**
     * Sets a claim builder.
     * Default : {@code eu.europa.esig.dss.attestation.sd.jwt.creation.DefaultSDJWTClaimBuilder}
     *
     * @param claimBuilder {@link SDJWTClaimBuilder}
     */
    public void setClaimBuilder(final SDJWTClaimBuilder claimBuilder) {
        Objects.requireNonNull(claimBuilder, "Claim builder cannot be null!");
        this.claimBuilder = claimBuilder;
    }

    @Override
    public DSSDocument buildPayload(SDJWTPayloadParameters payloadParameters) {
        final Map<String, Object> map = new LinkedHashMap<>();

        DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;
        if (payloadParameters.getDigestAlgorithm() != null) {
            map.put(SDJWTConstants._SD_ALG, digestAlgorithm.getSDJWTId());
        }

        final SecureRandom secureRandom = secureRandom(payloadParameters);
        final SDJWTClaimObject payload = getRootPayloadObject(payloadParameters, secureRandom);
        map.putAll(getAttestationClaimObjectValue(new DisclosureTraversalContext(), payload, digestAlgorithm, secureRandom, payloadParameters.isShuffleHashes()));

        return new InMemoryDocument(JsonUtil.toJson(map).getBytes());
    }

    private SDJWTClaimObject getRootPayloadObject(SDJWTPayloadParameters payloadParameters, SecureRandom secureRandom) {
        final SDJWTClaimObject payload = SDJWTClaimObject.create();

        payload.addChildren(getClaimBuilder().buildClaims(payloadParameters));

        if (payloadParameters.getDecoyDigestNumber() > 0) {
            DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                    payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;
            int digestLength = digestAlgorithm.getSaltLength();
            for (int i = 0; i < payloadParameters.getDecoyDigestNumber(); i++) {
                byte[] bytes = secureRandom.generateSeed(digestLength);
                payload.addDecoyDigest(DSSJsonUtils.toBase64Url(bytes));
            }
        }

        return payload;
    }

    private Object getClaimValue(final DisclosureTraversalContext dtx, final SDJWTClaim claim, final DigestAlgorithm digestAlgorithm, final SecureRandom secureRandom, final boolean shuffleHashes) {
        if (claim instanceof SDJWTClaimObject) {
            return getAttestationClaimObjectValue(dtx, (SDJWTClaimObject) claim, digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim instanceof SDJWTClaimArray) {
            return getAttestationClaimArrayValue(dtx, (SDJWTClaimArray) claim, digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Map) {
            return getClaimValue(dtx, toAttestationClaimObject((Map<?, ?>) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Collection) {
            return getClaimValue(dtx, toAttestationClaimArray((Collection<?>) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Object[]) {
            return getClaimValue(dtx, toAttestationClaimArray((Object[]) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);
        }

        return claim.getValue();
    }

    private SDJWTClaimObject toAttestationClaimObject(Map<?, ?> map) {
        final SDJWTClaimObject result = SDJWTClaimObject.create();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new DSSException("Map key must be String");
            }

            String name = (String) entry.getKey();
            Object value = entry.getValue();

            if (value instanceof SDJWTClaim) {
                result.addChild((SDJWTClaim) value);
            } else {
                result.addChild(SDJWTClaim.create(name, value));
            }
        }
        return result;
    }

    private SDJWTClaimArray toAttestationClaimArray(Object[] array) {
        final SDJWTClaimArray result = SDJWTClaimArray.create();
        for (Object item : array) {
            if (item instanceof SDJWTClaim) {
                result.addElement((SDJWTClaim) item);
            } else {
                result.addElement(SDJWTClaim.create(item));
            }
        }
        return result;
    }

    private SDJWTClaimArray toAttestationClaimArray(Collection<?> collection) {
        final SDJWTClaimArray result = SDJWTClaimArray.create();
        for (Object item : collection) {
            if (item instanceof SDJWTClaim) {
                result.addElement((SDJWTClaim) item);
            } else {
                result.addElement(SDJWTClaim.create(item));
            }
        }
        return result;
    }

    private Map<String, Object> getAttestationClaimObjectValue(final DisclosureTraversalContext dtx, final SDJWTClaimObject objectClaim,
                                                       final DigestAlgorithm digestAlgorithm, final SecureRandom secureRandom,
                                                       final boolean shuffleHashes) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> selectivelyDisclosableClaims = new ArrayList<>();

        objectClaim.getChildren().forEach(child -> {
            if (child.isSelectivelyDisclosable()) {
                selectivelyDisclosableClaims.add(getHashedDisclosure(dtx, child, digestAlgorithm, secureRandom, shuffleHashes));
            } else {
                result.put(child.getName(), getClaimValue(dtx, child, digestAlgorithm, secureRandom, shuffleHashes));
            }
        });

        selectivelyDisclosableClaims.addAll(objectClaim.getDecoyDigests());
        if (!selectivelyDisclosableClaims.isEmpty()) {
            if (shuffleHashes) {
                Collections.shuffle(selectivelyDisclosableClaims, secureRandom);
            }
            result.put(SDJWTConstants._SD, selectivelyDisclosableClaims);
        }

        return result;
    }

    private List<Object> getAttestationClaimArrayValue(final DisclosureTraversalContext dtx, final SDJWTClaimArray arrayClaim,
                                               final DigestAlgorithm digestAlgorithm, SecureRandom secureRandom,
                                               final boolean shuffleHashes) {
        List<Object> result = new ArrayList<>();
        List<Object> hashedElements = new ArrayList<>();

        arrayClaim.getElements().forEach(element -> {
            if (element.isSelectivelyDisclosable()) {
                Map<String, String> hashedElement = new LinkedHashMap<>();
                hashedElement.put(SDJWTConstants.HASH, getHashedDisclosure(dtx, element, digestAlgorithm, secureRandom, shuffleHashes));
                hashedElements.add(hashedElement);
            } else {
                result.add(getClaimValue(dtx, element, digestAlgorithm, secureRandom, shuffleHashes));
            }
        });

        arrayClaim.getDecoyDigests().forEach(decoyDigest -> {
            Map<String, String> decoyElement = new LinkedHashMap<>();
            decoyElement.put(SDJWTConstants.HASH, decoyDigest);
            hashedElements.add(decoyElement);
        });

        if (shuffleHashes) {
            Collections.shuffle(hashedElements, secureRandom);
        }
        result.addAll(hashedElements);

        return result;
    }

    private String getHashedDisclosure(DisclosureTraversalContext dtx, SDJWTClaim claim, DigestAlgorithm digestAlgorithm, SecureRandom secureRandom, boolean shuffleHashes) {
        return dtx.getHash(claim, () -> {
            SDJWTSelectiveDisclosure disclosure = getDisclosure(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes);
            Digest digest = disclosure.computeDigest(digestAlgorithm);
            return DSSJsonUtils.toBase64Url(digest.getValue());
        });
    }

    private SDJWTSelectiveDisclosure getDisclosure(DisclosureTraversalContext dtx, SDJWTClaim claim, DigestAlgorithm digestAlgorithm,
                                                   SecureRandom secureRandom, boolean shuffleHashes) {
        return dtx.getDisclosure(claim, () -> buildDisclosure(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes));
    }

    /**
     * Build the disclosure for the given claim
     *
     * @param dtx {@link DisclosureTraversalContext}
     * @param claim the claim
     * @param digestAlgorithm the digest algorithm
     * @param secureRandom {@link SecureRandom}
     * @param shuffleHashes if the hashes should be shuffled
     * @return {@link SDJWTSelectiveDisclosure}
     */
    protected SDJWTSelectiveDisclosure buildDisclosure(DisclosureTraversalContext dtx, SDJWTClaim claim, DigestAlgorithm digestAlgorithm, SecureRandom secureRandom, boolean shuffleHashes) {
        Object claimValue = getClaimValue(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes);
        String salt = claim.getSalt();
        if (Utils.isStringEmpty(salt)) {
            byte[] bytes = nextRandomSalt(secureRandom); // 16 * 8 = 128 bits
            salt = DSSJsonUtils.toBase64Url(bytes);
        }
        return disclosureBuilder.build(claim.getName(), claimValue, salt);
    }

    @Override
    public List<SDJWTSelectiveDisclosure> buildDisclosures(SDJWTPayloadParameters payloadParameters) {
        DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;

        SecureRandom secureRandom = secureRandom(payloadParameters);
        SDJWTClaimObject root = getRootPayloadObject(payloadParameters, secureRandom);
        return collectDisclosures(root, digestAlgorithm, secureRandom, payloadParameters.isShuffleHashes());
    }

    private List<SDJWTSelectiveDisclosure> collectDisclosures(final SDJWTClaimObject root, final DigestAlgorithm digestAlgorithm,
                                                              final SecureRandom secureRandom, final boolean shuffleHashes) {
        DisclosureTraversalContext dtx = new DisclosureTraversalContext();
        getAttestationClaimObjectValue(dtx, root, digestAlgorithm, secureRandom, shuffleHashes);
        return dtx.getDisclosures();
    }

    /**
     * Holds traversal state while generating an SD-JWT payload and its
     * associated disclosures.
     * <p>
     * This context ensures that disclosures and their corresponding hashes
     * are generated only once per claim instance and subsequently reused.
     * This guarantees deterministic disclosure generation for nested
     * selectively-disclosable claims and prevents inconsistencies caused by
     * recomputing disclosures with different salts.
     */
    private static class DisclosureTraversalContext {

        /**
         * Cache of generated disclosures keyed by claim instance.
         * <p>
         * An {@link IdentityHashMap} is used to ensure caching is based on
         * object identity rather than {@code equals}/{@code hashCode}.
         */
        private final Map<SDJWTClaim, SDJWTSelectiveDisclosure> disclosuresMap = new IdentityHashMap<>();

        /**
         * Cache of disclosure hashes keyed by claim instance.
         * <p>
         * This guarantees that a disclosure hash is computed only once and
         * reused whenever referenced by parent disclosures.
         */
        private final Map<SDJWTClaim, String> hashesMap = new IdentityHashMap<>();

        /**
         * Ordered list of generated disclosures.
         * <p>
         * The order reflects the first encounter of disclosures during claim
         * tree traversal and is used to produce deterministic output.
         */
        private final List<SDJWTSelectiveDisclosure> disclosuresList = new ArrayList<>();

        /**
         * Returns the disclosure associated with the given claim.
         * <p>
         * If no disclosure has been generated yet, the supplied function is
         * invoked to create and cache it. Newly created disclosures are also
         * recorded in the ordered disclosure list.
         *
         * @param claim {@link SDJWTClaim} for which a disclosure is requested
         * @param supplier supplies a disclosure when one is not yet cached
         * @return the cached or newly created disclosure
         */
        public SDJWTSelectiveDisclosure getDisclosure(SDJWTClaim claim, Supplier<SDJWTSelectiveDisclosure> supplier) {
            return disclosuresMap.computeIfAbsent(claim, c -> {
                SDJWTSelectiveDisclosure disclosure = supplier.get();
                disclosuresList.add(disclosure);
                return disclosure;
            });
        }

        /**
         * Returns the disclosure hash associated with the given claim.
         * <p>
         * If the hash has not yet been computed, the supplied function is
         * invoked and the resulting value is cached.
         *
         * @param claim {@link SDJWTClaim} for which a disclosure hash is requested
         * @param supplier supplies a hash when one is not yet cached
         * @return the cached or newly computed disclosure hash
         */
        public String getHash(SDJWTClaim claim, Supplier<String> supplier) {
            return hashesMap.computeIfAbsent(claim, k -> supplier.get());
        }

        /**
         * Returns the disclosures generated during traversal in deterministic
         * encounter order.
         *
         * @return a list of {@link SDJWTSelectiveDisclosure}s
         */
        public List<SDJWTSelectiveDisclosure> getDisclosures() {
            return disclosuresList;
        }

    }

}
