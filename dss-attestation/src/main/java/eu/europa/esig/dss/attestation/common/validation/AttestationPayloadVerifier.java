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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.DisclosureValidation;
import eu.europa.esig.dss.model.attestation.SelectiveDisclosure;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.spi.attestation.AttestationPayload;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Abstract implementation of attestation Payload Verifier
 *
 */
public abstract class AttestationPayloadVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(AttestationPayloadVerifier.class);

    /**
     * List of disclosures attached to the Attestation Presentation
     */
    protected List<SelectiveDisclosure> disclosures;

    /**
     * Extracted Digest Algorithm value to be used on hash of disclosures computation
     */
    protected DigestAlgorithm digestAlgorithm;

    /**
     * Computed list of disclosure validations
     */
    protected List<DisclosureValidation> disclosureValidations;

    /**
     * Computed payload, with the matching disclosures
     */
    protected AttestationPayload verifiedPayload;

    /**
     * Default constructor
     */
    protected AttestationPayloadVerifier() {
        // empty
    }

    /**
     * Sets the disclosures, requiring for attestation Payload selectively disclosable claims validation
     *
     * @param disclosures a list of {@link SelectiveDisclosure}s
     * @return this {@link AttestationPayloadVerifier}
     */
    public AttestationPayloadVerifier setDisclosures(List<SelectiveDisclosure> disclosures) {
        this.disclosures = disclosures;
        return this;
    }

    /**
     * This method returns a list of disclosure validation results.
     * Please call the method {@code #verify} before accessing the result of this method.
     *
     * @return a list of {@link DisclosureValidation}s
     */
    public List<DisclosureValidation> getDisclosureValidations() {
        if (disclosureValidations == null) {
            throw new IllegalStateException("The verification of the disclosures has not been yet performed! " +
                    "Please call #verify method before querying the results.");
        }
        return disclosureValidations;
    }

    /**
     * This method returns a payload map constructed using the provided disclosures.
     * Please call the method {@code #verify} before accessing the result of this method.
     *
     * @return {@link AttestationPayload}
     */
    public AttestationPayload getVerifiedPayload() {
        if (verifiedPayload == null) {
            throw new IllegalStateException("The verification of the payload and matching disclosures has not been yet performed! " +
                    "Please call #verify method before querying the results.");
        }
        return verifiedPayload;
    }

    /**
     * This method performs the verification process for the provided payload and disclosures
     * NOTE: The process can be executed only once
     */
    public abstract void verify();

    /**
     * This method verified the payload claims recursively and
     * re-constructs the original payload using the attached disclosures
     *
     * @param payloadMap {@link VerifiedClaimMap} representing the parse payload map
     * @return {@link VerifiedClaimMap} representing the processed payload
     */
    protected VerifiedClaimMap buildPayloadWithDisclosures(VerifiedClaimMap payloadMap) {
        VerifiedClaim payload = buildClaimWithDisclosures(payloadMap);
        if (!(payload instanceof VerifiedClaimMap)) {
            throw new IllegalStateException("The verified paylaod is expected to be of a ClaimMap type!");
        }
        ensureAllDisclosuresFound();
        return (VerifiedClaimMap) payload;
    }

    /**
     * This method looks recursively for protected hashes of selectively disclosable values and embeds them if needed.
     * This method also updates the {@code disclosureValidations} list.
     *
     * @param originalClaim {@link VerifiedClaim} to process
     * @return resulting {@link VerifiedClaim} build on the {@code originalClaim}
     */
    protected VerifiedClaim buildClaimWithDisclosures(VerifiedClaim originalClaim) {
        // re-build to ensure original is not modified
        if (originalClaim.isMapValueType()) {
            return buildClaimMap((VerifiedClaimMap) originalClaim);
        } else if (originalClaim.isArrayValueType()) {
            return buildClaimArray((VerifiedClaimArray) originalClaim);
        }
        // in other cases, keep the original
        return originalClaim;
    }

    private VerifiedClaim buildClaimMap(VerifiedClaimMap originalClaimMap) {
        final Map<String, VerifiedClaim> result = new HashMap<>(); // TODO : LinkedHashMap ?
        for (Map.Entry<String, VerifiedClaim> entry : originalClaimMap.getMapValue().entrySet()) {
            String headerName = entry.getKey();
            VerifiedClaim claimValue = entry.getValue();
            if (isSignedDisclosuresHeader(headerName)) {
                Map<String, VerifiedClaim> processedClaims = buildSelectiveDisclosureMap(claimValue);
                result.putAll(processedClaims);

            } else if (isToSkipHeader(headerName)) {
                // skip _sd_alg values
                continue;

            } else {
                claimValue = buildClaimWithDisclosures(claimValue);
                if (claimValue != null) {
                    result.put(headerName, claimValue);
                }
            }

        }
        return createClaim(originalClaimMap.getName(), originalClaimMap.getParent(), result, originalClaimMap.isSelectivelyDisclosable());
    }

    /**
     * Returns whether the {@code headerName} corresponds to a header containing hashes of signed data items
     *
     * @param headerName {@link String} to check
     * @return TRUE if the header name corresponds to a header name containing hashes of signed data items,
     *         FALSE otherwise
     */
    protected abstract boolean isSignedDisclosuresHeader(String headerName);

    /**
     * Returns whether the header is to be skipped from the final payload map (used for technical headers).
     * NOTE: a header containing hashes of signed data items does not need to be handled in this method.
     *
     * @param headerName {@link String} to check
     * @return TRUE if the header with the given name is to be skipped, FALSE otherwise
     */
    protected abstract boolean isToSkipHeader(String headerName);

    /**
     * Creates a new claim using the provided information
     *
     * @param claimName {@link String} name of the corresponding header key used to incorporate the claim
     * @param parentClaim {@link VerifiedClaim} parent of the claim to be created
     * @param claimValue value of the claim
     * @param isSelectivelyDisclosable whether the claim was provided as a selective disclosure
     * @return {@link VerifiedClaim}
     */
    protected abstract VerifiedClaim createClaim(String claimName, VerifiedClaim parentClaim, Object claimValue, boolean isSelectivelyDisclosable);

    private VerifiedClaim buildClaimArray(VerifiedClaimArray originalClaimArray) {
        final List<VerifiedClaim> result = new ArrayList<>();
        for (VerifiedClaim claimItem : originalClaimArray.getListValue()) {
            VerifiedClaim hashClaim = getClaimHashItem(claimItem);
            if (hashClaim != null) {
                claimItem = buildSelectiveDisclosure(hashClaim, disclosures);
            } else {
                claimItem = buildClaimWithDisclosures(claimItem);
            }
            if (claimItem != null) {
                result.add(claimItem);
            }
        }
        return createClaim(originalClaimArray.getName(), originalClaimArray.getParent(), result, originalClaimArray.isSelectivelyDisclosable());
    }

    /**
     * Gets a claim when its value corresponds to a hash of a selectively disclosable item (e.g. "..." in SD-JWT)
     *
     * @param claim {@link VerifiedClaim} to check
     * @return {@link VerifiedClaim} hash value of the claim, when applicable. NULL otherwise.
     */
    protected abstract VerifiedClaim getClaimHashItem(VerifiedClaim claim);

    /**
     * Builds a list of hash claims from a content of a claim containing protected hashes
     *
     * @param claim {@link VerifiedClaim} to process
     * @return a map representing the extracted disclosures as their corresponding names as keys
     */
    protected abstract Map<String, VerifiedClaim> buildSelectiveDisclosureMap(VerifiedClaim claim);

    /**
     * Builds a claim based on the provided selectively disclosable value
     *
     * @param hashClaim {@link VerifiedClaim} representing the hash value of the item
     * @param disclosures a list of {@link SelectiveDisclosure}s to look for a matching value from
     * @return {@link VerifiedClaim} resulting in a processing of disclosable claims
     */
    protected VerifiedClaim buildSelectiveDisclosure(VerifiedClaim hashClaim, List<SelectiveDisclosure> disclosures) {
        DisclosureValidation disclosureValidation = validateHashClaim(hashClaim, disclosures);
        return getDisclosedClaim(disclosureValidation);
    }

    /**
     * Gets the claim validated from the provided disclosure
     *
     * @param disclosureValidation {@link DisclosureValidation}
     * @return {@link VerifiedClaim}
     */
    protected VerifiedClaim getDisclosedClaim(DisclosureValidation disclosureValidation) {
        if (disclosureValidation != null) {
            if (disclosureValidation.isFound() && disclosureValidation.isIntact() && disclosureValidation.getDisclosure() != null) {
                return disclosureValidation.getVerifiedClaim();
            }
        }
        return null;
    }

    /**
     * Performs verification of the hash claim. The method looks for a corresponding provided disclosure and
     * returns the corresponding validation result.
     *
     * @param hashClaim {@link VerifiedClaim} to verify
     * @param disclosures a list of {@link SelectiveDisclosure}s to look for a matching value from
     * @return {@link DisclosureValidation}
     */
    protected DisclosureValidation validateHashClaim(VerifiedClaim hashClaim, List<SelectiveDisclosure> disclosures) {
        if (hashClaim == null) {
            return null;
        }
        byte[] hashBytes = getHashBytes(hashClaim);
        if (hashBytes == null) {
            return null;
        }

        DisclosureValidation disclosureValidation;
        SelectiveDisclosure disclosure = getDisclosureForClaimHash(hashBytes, disclosures);
        if (disclosure != null) {
            disclosureValidation = getDisclosureValidation(disclosure);
            disclosureValidation.setType(DigestMatcherType.SELECTIVE_DISCLOSURE);
            disclosureValidation.setDigest(new Digest(digestAlgorithm, hashBytes));
            disclosureValidation.setFound(true);
            disclosureValidation.setIntact(true);

        } else {
            disclosureValidation = new DisclosureValidation();
            disclosureValidation.setType(DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM);
            disclosureValidation.setDigest(new Digest(digestAlgorithm, hashBytes));
        }
        disclosureValidations.add(disclosureValidation);
        return disclosureValidation;
    }

    /**
     * Gets embedded hash bytes from the claim value
     *
     * @param hashClaim {@link VerifiedClaim}
     * @return byte array representing the resulted hash value
     */
    protected abstract byte[] getHashBytes(VerifiedClaim hashClaim);

    private SelectiveDisclosure getDisclosureForClaimHash(byte[] sdHash, List<SelectiveDisclosure> disclosures) {
        if (Utils.isCollectionEmpty(disclosures)) {
            LOG.debug("No disclosures has been provided. Unable to validate a selectively disclosable claim.");
            return null;
        }
        for (SelectiveDisclosure disclosure : disclosures) {
            Digest disclosureDigest = disclosure.getDigest(digestAlgorithm);
            if (disclosureDigest != null && !disclosureDigest.isEmpty() && Arrays.equals(sdHash, disclosureDigest.getValue())) {
                return disclosure;
            }
        }
        return null;
    }

    /**
     * This method ensures that attestation contains hashes for all disclosures attached
     */
    protected void ensureAllDisclosuresFound() {
        List<DisclosureValidation> disclosureValidations = getDisclosureValidations();
        if (disclosureValidations == null) {
            throw new IllegalStateException("Disclosure validations have not yet been build! The method #verify shall be called first!");
        }
        List<SelectiveDisclosure> notFoundDisclosures = disclosures.stream()
                .filter(d -> disclosureValidations.stream().noneMatch(
                        v -> d.equals(v.getDisclosure()))).collect(Collectors.toList());

        cleanOrphanReferences(disclosureValidations, notFoundDisclosures);

        for (SelectiveDisclosure disclosure : notFoundDisclosures) {
            if (disclosure == null) {
                continue;
            }
            DisclosureValidation disclosureValidation = getDisclosureValidation(disclosure);
            disclosureValidation.setType(DigestMatcherType.SELECTIVE_DISCLOSURE);
            disclosureValidation.setDigest(disclosure.getDigest(digestAlgorithm));
            disclosureValidation.setFound(true);
            disclosureValidation.setIntact(false);
            disclosureValidations.add(disclosureValidation);
        }
    }

    /**
     * Gets a DisclosureValidation object for the given {@code SelectiveDisclosure}
     *
     * @param disclosure {@link SelectiveDisclosure}
     * @return {@link DisclosureValidation}
     */
    protected abstract DisclosureValidation getDisclosureValidation(SelectiveDisclosure disclosure);

    /**
     * This method removes orphan references for other disclosures that were provided but not matching
     *
     * @param disclosureValidations a list of {@link DisclosureValidation}s
     * @param notFoundDisclosures a list od {@link SelectiveDisclosure}s
     */
    protected void cleanOrphanReferences(List<DisclosureValidation> disclosureValidations, List<SelectiveDisclosure> notFoundDisclosures) {
        List<DisclosureValidation> orphanRefs = getOrphanDisclosureValidations();
        if (Utils.collectionSize(orphanRefs) == 1 && Utils.collectionSize(notFoundDisclosures) == 1) {
            disclosureValidations.remove(orphanRefs.iterator().next());
        }
    }

    /**
     * Gets a list of orphan disclosure validations
     *
     * @return a list of {@link DisclosureValidation}s
     */
    protected List<DisclosureValidation> getOrphanDisclosureValidations() {
        return disclosureValidations.stream().filter(
                r -> DigestMatcherType.ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == r.getType()).collect(Collectors.toList());
    }

    /**
     * Gets the digest algorithm used for hashes computation of selective disclosures
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        if (digestAlgorithm == null) {
            throw new IllegalStateException("Please call method #verify before accessing the Digestalgorithm value!");
        }
        return digestAlgorithm;
    }

}
