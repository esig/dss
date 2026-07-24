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
package eu.europa.esig.dss.eaa.common.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.eaa.DisclosureValidation;
import eu.europa.esig.dss.model.eaa.ValidationDisclosure;
import eu.europa.esig.dss.model.eaa.claim.Claim;
import eu.europa.esig.dss.model.eaa.claim.ClaimArray;
import eu.europa.esig.dss.model.eaa.claim.ClaimMap;
import eu.europa.esig.dss.spi.eaa.AttestationPayload;
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
 * Abstract implementation of EAA Payload Verifier
 *
 */
public abstract class AttestationPayloadVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(AttestationPayloadVerifier.class);

    /**
     * List of disclosures attached to the Attestation Presentation
     */
    protected List<ValidationDisclosure> disclosures;

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
    public AttestationPayloadVerifier() {
        // empty
    }

    /**
     * Sets the disclosures, requiring for EAA Payload selectively disclosable claims validation
     *
     * @param disclosures a list of {@link ValidationDisclosure}s
     * @return this {@link AttestationPayloadVerifier}
     */
    public AttestationPayloadVerifier setDisclosures(List<ValidationDisclosure> disclosures) {
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
     * @param payloadMap {@link ClaimMap} representing the parse payload map
     * @return {@link ClaimMap} representing the processed payload
     */
    protected ClaimMap buildPayloadWithDisclosures(ClaimMap payloadMap) {
        Claim verifiedPayload = buildClaimWithDisclosures(payloadMap);
        if (!(verifiedPayload instanceof ClaimMap)) {
            throw new IllegalStateException("The verified paylaod is expected to be of a ClaimMap type!");
        }
        ensureAllDisclosuresFound();
        return (ClaimMap) verifiedPayload;
    }

    /**
     * This method looks recursively for protected hashes of selectively disclosable values and embeds them if needed.
     * This method also updates the {@code disclosureValidations} list.
     *
     * @param originalClaim {@link Claim} to process
     * @return resulting {@link Claim} build on the {@code originalClaim}
     */
    protected Claim buildClaimWithDisclosures(Claim originalClaim) {
        // re-build to ensure original is not modified
        if (originalClaim.isMapValueType()) {
            return buildClaimMap((ClaimMap) originalClaim);
        } else if (originalClaim.isArrayValueType()) {
            return buildClaimArray((ClaimArray) originalClaim);
        }
        // in other cases, keep the original
        return originalClaim;
    }

    private Claim buildClaimMap(ClaimMap originalClaimMap) {
        final Map<String, Claim> result = new HashMap<>(); // TODO : LinkedHashMap ?
        for (Map.Entry<String, Claim> entry : originalClaimMap.getMapValue().entrySet()) {
            String headerName = entry.getKey();
            Claim claimValue = entry.getValue();
            if (isSignedDisclosuresHeader(headerName)) {
                Map<String, Claim> processedClaims = buildSelectivelyDisclosableClaimMap(claimValue);
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
     * @param parentClaim {@link Claim} parent of the claim to be created
     * @param claimValue value of the claim
     * @param isSelectivelyDisclosable whether the claim was provided as a selective disclosure
     * @return {@link Claim}
     */
    protected abstract Claim createClaim(String claimName, Claim parentClaim, Object claimValue, boolean isSelectivelyDisclosable);

    private Claim buildClaimArray(ClaimArray originalClaimArray) {
        final List<Claim> result = new ArrayList<>();
        for (Claim claimItem : originalClaimArray.getListValue()) {
            Claim hashClaim = getClaimHashItem(claimItem);
            if (hashClaim != null) {
                claimItem = buildSelectivelyDisclosableClaim(hashClaim, disclosures);
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
     * @param claim {@link Claim} to check
     * @return {@link Claim} hash value of the claim, when applicable. NULL otherwise.
     */
    protected abstract Claim getClaimHashItem(Claim claim);

    /**
     * Builds a list of hash claims from a content of a claim containing protected hashes
     *
     * @param claim {@link Claim} to process
     * @return a map representing the extracted disclosures as their corresponding names as keys
     */
    protected abstract Map<String, Claim> buildSelectivelyDisclosableClaimMap(Claim claim);

    /**
     * Builds a claim based on the provided selectively disclosable value
     *
     * @param hashClaim {@link Claim} representing the hash value of the item
     * @param disclosures a list of {@link ValidationDisclosure}s to look for a matching value from
     * @return {@link Claim} resulting in a processing of disclosable claims
     */
    protected Claim buildSelectivelyDisclosableClaim(Claim hashClaim, List<ValidationDisclosure> disclosures) {
        DisclosureValidation disclosureValidation = validateHashClaim(hashClaim, disclosures);
        return getDisclosedClaim(disclosureValidation);
    }

    /**
     * Gets the claim validated from the provided disclosure
     *
     * @param disclosureValidation {@link DisclosureValidation}
     * @return {@link Claim}
     */
    protected Claim getDisclosedClaim(DisclosureValidation disclosureValidation) {
        if (disclosureValidation != null) {
            if (disclosureValidation.isFound() && disclosureValidation.isIntact() && disclosureValidation.getDisclosure() != null) {
                return disclosureValidation.getDisclosure().getClaimValue();
            }
        }
        return null;
    }

    /**
     * Performs verification of the hash claim. The method looks for a corresponding provided disclosure and
     * returns the corresponding validation result.
     *
     * @param hashClaim {@link Claim} to verify
     * @param disclosures a list of {@link ValidationDisclosure}s to look for a matching value from
     * @return {@link DisclosureValidation}
     */
    protected DisclosureValidation validateHashClaim(Claim hashClaim, List<ValidationDisclosure> disclosures) {
        if (hashClaim == null) {
            return null;
        }
        byte[] hashBytes = getHashBytes(hashClaim);
        if (hashBytes == null) {
            return null;
        }

        DisclosureValidation disclosureValidation;
        ValidationDisclosure disclosure = getDisclosureForClaimHash(hashBytes, disclosures);
        if (disclosure != null) {
            disclosureValidation = new DisclosureValidation(disclosure);
            disclosureValidation.setType(DigestMatcherType.EAA_DISCLOSURE);
            disclosureValidation.setDigest(new Digest(digestAlgorithm, hashBytes));
            disclosureValidation.setFound(true);
            disclosureValidation.setIntact(true);

        } else {
            disclosureValidation = new DisclosureValidation();
            disclosureValidation.setType(DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM);
            disclosureValidation.setDigest(new Digest(digestAlgorithm, hashBytes));
        }
        disclosureValidations.add(disclosureValidation);
        return disclosureValidation;
    }

    /**
     * Gets embedded hash bytes from the claim value
     *
     * @param hashClaim {@link Claim}
     * @return byte array representing the resulted hash value
     */
    protected abstract byte[] getHashBytes(Claim hashClaim);

    private ValidationDisclosure getDisclosureForClaimHash(byte[] sdHash, List<ValidationDisclosure> disclosures) {
        if (Utils.isCollectionEmpty(disclosures)) {
            LOG.debug("No disclosures has been provided. Unable to validate a selectively disclosable claim.");
            return null;
        }
        for (ValidationDisclosure disclosure : disclosures) {
            Digest disclosureDigest = disclosure.getDigest(digestAlgorithm);
            if (disclosureDigest != null && !disclosureDigest.isEmpty() && Arrays.equals(sdHash, disclosureDigest.getValue())) {
                return disclosure;
            }
        }
        return null;
    }

    /**
     * This method ensures that EAA contains hashes for all disclosures attached
     */
    protected void ensureAllDisclosuresFound() {
        List<DisclosureValidation> disclosureValidations = getDisclosureValidations();
        if (disclosureValidations == null) {
            throw new IllegalStateException("Disclosure validations have not yet been build! The method #verify shall be called first!");
        }
        List<ValidationDisclosure> notFoundDisclosures = disclosures.stream()
                .filter(d -> disclosureValidations.stream().noneMatch(
                        v -> d.equals(v.getDisclosure()))).collect(Collectors.toList());

        cleanOrphanReferences(disclosureValidations, notFoundDisclosures);

        for (ValidationDisclosure disclosure : notFoundDisclosures) {
            if (disclosure == null) {
                continue;
            }
            DisclosureValidation disclosureValidation = new DisclosureValidation(disclosure);
            disclosureValidation.setType(DigestMatcherType.EAA_DISCLOSURE);
            disclosureValidation.setDigest(disclosure.getDigest(digestAlgorithm));
            disclosureValidation.setFound(true);
            disclosureValidation.setIntact(false);
            disclosureValidations.add(disclosureValidation);
        }
    }

    /**
     * This method removes orphan references for other disclosures that were provided but not matching
     *
     * @param disclosureValidations a list of {@link DisclosureValidation}s
     * @param notFoundDisclosures a list od {@link ValidationDisclosure}s
     */
    protected void cleanOrphanReferences(List<DisclosureValidation> disclosureValidations, List<ValidationDisclosure> notFoundDisclosures) {
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
                r -> DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == r.getType()).collect(Collectors.toList());
    }

    /**
     * Gets the digest algorithm used for hashes computation of selective disclosures
     *
     * @return {@link DigestAlgorithm}
     */
    public DigestAlgorithm getDigestAlgorithm() {
        if (digestAlgorithm == null) {
            throw new IllegalStateException("Please call method #verify before accessing the DigestAlgortihm value!");
        }
        return digestAlgorithm;
    }

}
