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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.common.validation.AttestationPayloadVerifier;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.eaa.ValidationDisclosure;
import eu.europa.esig.dss.model.eaa.claim.Claim;
import eu.europa.esig.dss.model.eaa.claim.ClaimMap;
import eu.europa.esig.dss.model.eaa.claim.ClaimString;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * This class verifies selectively disclosable claims, when provided, and computes the combined version of
 * the EAA payload, which includes the non-selectively disclosable claims as well as disclosed claims.
 * This class requires execution of {@code #verify} method before accessing the validation results.
 *
 */
public class SDJWTPayloadVerifier extends AttestationPayloadVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTPayloadVerifier.class);

    /**
     * Payload map to be verified
     */
    private final Map<String, Object> jsonPayload;

    /**
     * Default constructor
     *
     * @param jsonPayload JSON payload to be verified
     */
    public SDJWTPayloadVerifier(final Map<String, Object> jsonPayload) {
        Objects.requireNonNull(jsonPayload, "Payload cannot be null!");
        this.jsonPayload = jsonPayload;
    }

    /**
     * This method performs the verification process for the provided payload and disclosures
     * NOTE: The process can be executed only once
     */
    @Override
    public void verify() {
        ClaimMap originalPayloadMap = parseJsonPayload();
        this.disclosureValidations = new ArrayList<>();
        this.digestAlgorithm = getSDDigestAlgorithm(originalPayloadMap);
        ClaimMap verifiedPayloadMap = buildPayloadWithDisclosures(originalPayloadMap);
        this.verifiedPayload = new SDJWTPayload(verifiedPayloadMap);
    }

    private ClaimMap parseJsonPayload() {
        try {
            Claim payloadClaim = SDJWTUtils.createClaim(jsonPayload);
            if (payloadClaim.isMapValueType()) {
                return (ClaimMap) payloadClaim;
            } else {
                throw new IllegalInputException("SD-JWT Payload shall be of a JSON Map type!");
            }
        } catch (Exception e) {
            throw new DSSException(String.format("An error occurred on reading SD-JWT Payload : %s", e.getMessage()), e);
        }
    }

    private DigestAlgorithm getSDDigestAlgorithm(ClaimMap payloadMap) {
        ClaimString _sd_alg = payloadMap.getAsString(SDJWTConstants._SD_ALG);
        if (_sd_alg != null) {
            String sdAlgId = _sd_alg.getStringValue();
            try {
                return DigestAlgorithm.forSdJwtId(sdAlgId);
            } catch (IllegalArgumentException e) {
                LOG.warn("Unable to find a corresponding DigestAlgorithm for SD-JWT claim for value '{}'!", sdAlgId);
                return null;
            }
        }
        /*
         * 4.2.3. Hashing Disclosures (draft-ietf-oauth-selective-disclosure-jwt-22)
         *
         * For embedding references to the Disclosures in the SD-JWT, each Disclosure is hashed
         * using the hash algorithm specified in the _sd_alg claim described in Section 4.1.1,
         * or SHA-256 if no algorithm is specified.
         */
        return DigestAlgorithm.SHA256;
    }

    @Override
    protected boolean isSignedDisclosuresHeader(String headerName) {
        return SDJWTConstants._SD.equals(headerName);
    }

    @Override
    protected Map<String, Claim> buildSelectivelyDisclosableClaimMap(Claim _sdClaim) {
        if (!_sdClaim.isArrayValueType()) {
            LOG.warn("_sd header shall be of type of JSON array!");
            return Collections.emptyMap();
        }

        final Map<String, Claim> result = new HashMap<>();

        List<Claim> sdClaims = _sdClaim.getListValue();
        for (Claim sdClaim : sdClaims) {
            Claim claim = buildSelectivelyDisclosableClaim(sdClaim, disclosures);
            if (claim != null) {
                if (claim.getName() != null) {
                    result.put(claim.getName(), claim);
                } else {
                    LOG.warn("No claim name is present for the disclosure when matching a '{}' value!", _sdClaim.getName());
                }
            }
        }

        return result;
    }

    @Override
    protected Claim buildSelectivelyDisclosableClaim(Claim hashClaim, List<ValidationDisclosure> disclosures) {
        Claim claim = super.buildSelectivelyDisclosableClaim(hashClaim, disclosures);
        if (claim != null) {
            return buildClaimWithDisclosures(claim); // process recursively
        }
        return null;
    }

    @Override
    protected boolean isToSkipHeader(String headerName) {
        return SDJWTConstants._SD_ALG.equals(headerName); // _sd_alg header
    }

    @Override
    protected Claim createClaim(String claimName, Claim parentClaim, Object claimValue, boolean isSelectivelyDisclosable) {
        return SDJWTUtils.createClaim(claimName, parentClaim, claimValue, isSelectivelyDisclosable);
    }

    @Override
    protected Claim getClaimHashItem(Claim claim) {
        if (claim.isMapValueType()) {
            ClaimMap claimMap = (ClaimMap) claim;
            if (claimMap.getSize() == 1) {
                return claimMap.getAsString(SDJWTConstants.HASH);
            }
        }
        return null;
    }

    @Override
    protected byte[] getHashBytes(Claim hashClaim) {
        if (!hashClaim.isStringValueType()) {
            LOG.warn("Selective disclosure hash claim value shall be of String type!");
            return null;
        }
        String sdB64Url = hashClaim.getStringValue();
        if (!DSSJsonUtils.isBase64UrlEncoded(sdB64Url)) {
            LOG.warn("Selective disclosure hash claim value shall be base64url encoded!");
            return null;
        }
        try {
            return DSSJsonUtils.fromBase64Url(sdB64Url);

        } catch (Exception e) {
            String errorMessage = "An error occurred on selective disclosure hash decoding : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, e.getMessage());
            }
            return null;
        }
    }

}
