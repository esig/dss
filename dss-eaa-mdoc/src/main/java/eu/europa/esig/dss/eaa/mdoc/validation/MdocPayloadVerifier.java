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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.eaa.common.validation.AttestationPayloadVerifier;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.MdocUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.eaa.ValidationDisclosure;
import eu.europa.esig.dss.model.eaa.DisclosureValidation;
import eu.europa.esig.dss.model.eaa.claim.Claim;
import eu.europa.esig.dss.model.eaa.claim.ClaimMap;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * This class verifies issuer signed items, when provided, and computes the combined version of
 * the EAA payload, which includes the MobileSecurityObject as defined in ISO 18013-5
 * "9.1.2.4 Signing method and structure for MSO" as well as issuer signed items.
 * This class requires execution of {@code #verify} method before accessing the validation results.
 *
 */
public class MdocPayloadVerifier extends AttestationPayloadVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(MdocPayloadVerifier.class);

    /**
     * Payload to be verified
     */
    private final CBORObject cborPayload;

    /**
     * Document type
     */
    private String docType;

    /**
     * Default constructor
     *
     * @param cborPayload {@link String} JSON payload to be verified
     */
    public MdocPayloadVerifier(final CBORObject cborPayload) {
        Objects.requireNonNull(cborPayload, "Payload cannot be null!");
        this.cborPayload = cborPayload;
    }

    /**
     * Sets the document type
     *
     * @param docType {@link String}
     * @return {@link MdocPayloadVerifier}
     */
    public MdocPayloadVerifier setDocType(String docType) {
        this.docType = docType;
        return this;
    }

    /**
     * This method performs the verification process for the provided payload and disclosures
     * NOTE: The process can be executed only once
     */
    @Override
    public void verify() {
        ClaimMap originalPayloadMap = parseCborPayload();
        this.disclosureValidations = new ArrayList<>();
        this.digestAlgorithm = getDigestAlgorithm(originalPayloadMap);
        ClaimMap verifiedPayloadMap = buildPayloadWithDisclosures(originalPayloadMap);
        this.verifiedPayload = new MdocAttestationPayload(verifiedPayloadMap, docType);
    }

    /**
     * Parses the {@code cborPayload} to a {@code ClaimMap} object
     *
     * @return {@link ClaimMap}
     */
    protected ClaimMap parseCborPayload() {
        CBORMap mso = getMobileSecurityObject();
        return (ClaimMap) MdocUtils.createClaim(mso);
    }

    private CBORMap getMobileSecurityObject() {
        if (!cborPayload.isByteString()) {
            throw new IllegalInputException("COSE payload shall be encoded as a CBOR byte string!");
        }
        try {
            CBORByteString payloadByteString = (CBORByteString) cborPayload;
            CBORObject msoObject = CBORUtils.parseCbor(payloadByteString.getValueAsBytes());
            if (!msoObject.isByteString()) {
                throw new IllegalInputException("MobileSecurityObjectBytes shall be encoded as a CBOR byte string!");
            }
            return new CBORMap((CBORByteString) msoObject);

        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "An error occurred on MobileSecurityObject processing : %s", e.getMessage()), e);
        }
    }

    private DigestAlgorithm getDigestAlgorithm(ClaimMap originalPayloadMap) {
        ClaimString digestAlgorithm = originalPayloadMap.getAsString(MdocConstants.DIGEST_ALGORITHM);
        if (digestAlgorithm != null) {
            String msoDigestAlgorithmId = digestAlgorithm.getValueAsString();
            try {
                return DigestAlgorithm.forMSO(msoDigestAlgorithmId);
            } catch (IllegalArgumentException e) {
                LOG.warn("Unable to find a corresponding DigestAlgorithm for the value extracted " +
                        "from a MobileSecurityObject '{}'!", msoDigestAlgorithmId);
            }
        }
        return null;
    }

    @Override
    protected boolean isSignedDisclosuresHeader(String headerName) {
        return MdocConstants.VALUE_DIGEST.equals(headerName);
    }

    @Override
    protected Map<String, Claim> buildSelectivelyDisclosableClaimMap(Claim valueDigestsClaim) {
        if (!valueDigestsClaim.isMapValueType()) {
            LOG.warn("valueDigests header shall be of a CBOR Map type!");
            return Collections.emptyMap();
        }

        final Map<String, Claim> result = new HashMap<>();

        Map<String, Claim> valueDigestsMap = valueDigestsClaim.getMapValue();
        for (Map.Entry<String, Claim> valueDigestsEntry : valueDigestsMap.entrySet()) {
            String namespace = valueDigestsEntry.getKey();
            Claim digestIDs = valueDigestsEntry.getValue();
            if (!digestIDs.isMapValueType()) {
                LOG.warn("DigestIDs object shall be of a CBOR Map type! The value is skipped.");
                continue;
            }

            for (Map.Entry<String, Claim> digestIDsEntry : digestIDs.getMapValue().entrySet()) {
                String digestId = digestIDsEntry.getKey();
                if (!Utils.isStringDigits(digestId)) {
                    LOG.warn("DigestID key shall be represented by an unsigned integer! The value is skipped.");
                    continue;
                }
                Claim digest = digestIDsEntry.getValue();

                long digestIdLong = Long.parseLong(digestId);
                List<ValidationDisclosure> disclosureCandidates = getDisclosureByNamespaceAndId(namespace, digestIdLong);
                Claim claim = buildSelectivelyDisclosableClaim(digest, disclosureCandidates, namespace, digestIdLong);
                if (claim != null) {
                    if (claim.getName() != null) {
                        result.put(claim.getName(), claim);
                    } else {
                        LOG.warn("No claim name is present for a matching disclosure!");
                    }
                }
            }

        }
        return result;
    }

    private List<ValidationDisclosure> getDisclosureByNamespaceAndId(String namespace, Long digestId) {
        return disclosures.stream()
                .filter(d -> namespace.equals((d).getNamespace()) && digestId.equals((d).getDigestId()))
                .collect(Collectors.toList());
    }

    @Override
    protected void cleanOrphanReferences(List<DisclosureValidation> disclosureValidations, List<ValidationDisclosure> notFoundDisclosures) {
        List<DisclosureValidation> orphanDisclosureValidations = getOrphanDisclosureValidations();
        for (ValidationDisclosure disclosure : notFoundDisclosures) {
            if (disclosure.getNamespace() != null && disclosure.getDigestId() != null) {
                List<DisclosureValidation> matchingValidations = orphanDisclosureValidations.stream().filter(
                                v -> disclosure.getNamespace().equals(v.getNamespace()) && disclosure.getDigestId().equals(v.getDigestId()))
                        .collect(Collectors.toList());
                if (Utils.collectionSize(matchingValidations) == 1) {
                    disclosureValidations.remove(matchingValidations.iterator().next());
                }
            }
        }
    }

    /**
     * Validates the disclosure and returns the extracted value
     *
     * @param hashClaim {@link Claim}
     * @param disclosures a list of {@link ValidationDisclosure}s
     * @param namespace {@link String}
     * @param digestId {@link Long}
     * @return {@link Claim}
     */
    protected Claim buildSelectivelyDisclosableClaim(Claim hashClaim, List<ValidationDisclosure> disclosures, String namespace, Long digestId) {
        DisclosureValidation disclosureValidation = validateHashClaim(hashClaim, disclosures, namespace, digestId);
        return getDisclosedClaim(disclosureValidation);
    }

    /**
     * Validates the {@code hashClaim} against a list of {@code disclosures} and returns the resulted {@code DisclosureValidation}
     *
     * @param hashClaim {@link Claim}
     * @param disclosures a list of {@link ValidationDisclosure}s
     * @param namespace {@link String}
     * @param digestId {@link Long}
     * @return {@link DisclosureValidation}
     */
    protected DisclosureValidation validateHashClaim(Claim hashClaim, List<ValidationDisclosure> disclosures, String namespace, Long digestId) {
        DisclosureValidation disclosureValidation = super.validateHashClaim(hashClaim, disclosures);
        disclosureValidation.setId(hashClaim.getName());
        disclosureValidation.setNamespace(namespace);
        disclosureValidation.setDigestId(digestId);
        return disclosureValidation;
    }

    @Override
    protected boolean isToSkipHeader(String headerName) {
        return MdocConstants.DIGEST_ALGORITHM.equals(headerName);
    }

    @Override
    protected Claim createClaim(String claimName, Claim parentClaim, Object claimValue, boolean isSelectivelyDisclosable) {
        return MdocUtils.createClaim(claimName, parentClaim, claimValue, isSelectivelyDisclosable);
    }

    @Override
    protected Claim getClaimHashItem(Claim claim) {
        // not applicable for mdoc
        return null;
    }

    @Override
    protected byte[] getHashBytes(Claim hashClaim) {
        if (!hashClaim.isBinaryValueType()) {
            LOG.warn("Digest object shall be of a CBOR Byte String type! The value is skipped.");
            return null;
        }
        return hashClaim.getBinaryValue();
    }

}
