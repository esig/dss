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

import eu.europa.esig.dss.attestation.common.creation.AbstractAttestationPayloadParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Provides configuration for the SD-JWT payload creation
 *
 */
public class SDJWTPayloadParameters extends AbstractAttestationPayloadParameters {

    /** attestation issuer subject */
    private String issuer;

    /** Contains the type of the key used for the device authentication. */
    private String deviceKeyType;

    /** Contains the certificate chain used for the device authentication. */
    private List<CertificateToken> deviceX509CertificateChain;

    /** Contains the digest of the certificate used for the device authentication. */
    private Digest deviceX509CertificateThumbprint;

    /** Contains the location where the certificate used for device authentication can be accessed from. */
    private String deviceX509CertificateUrl;

    // draft-ietf-oauth-sd-jwt-vc-13

    /** Type identifier of the embedded Verifiable Credential. */
    private String verifiableCredentialsType;

    /** Integrity metadata or cryptographic binding associated with the Verifiable Credential. */
    private Digest verifiableCredentialsTypeIntegrity;

    /** Catalogue of parameters to be made selectively disclosable */
    private final SDJWTClaimParameters selectivelyDisclosableParameters = new SDJWTClaimParameters();

    /** Catalogue of parameters to be made non-selectively disclosable */
    private final SDJWTClaimParameters nonSelectivelyDisclosableParameters = new SDJWTClaimParameters();

    /**
     * Default constructor to instantiate SD-JWT Payload parameters
     */
    public SDJWTPayloadParameters() {
        // empty
    }

    /**
     * Gets the attestation issuer subject
     *
     * @return {@link String}
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the attestation issue subject
     *
     * @param issuer {@link String}
     */
    public void setIssuer(final String issuer) {
        this.issuer = issuer;
    }

    /**
     * Gets the type of the key used for the device authentication
     *
     * @return {@link String}
     */
    public String getDeviceKeyType() {
        return deviceKeyType;
    }

    /**
     * Sets the type of the key used for the device authentication.
     * To be used only when a representation of an attestation subject certificate is provided, but not a device public key.
     *
     * @param deviceKeyType {@link String}
     */
    public void setDeviceKeyType(String deviceKeyType) {
        this.deviceKeyType = deviceKeyType;
    }

    /**
     * Gets a certificate chain used for the device authentication
     *
     * @return a list of {@link CertificateToken}s
     */
    public List<CertificateToken> getDeviceX509CertificateChain() {
        return deviceX509CertificateChain;
    }

    /**
     * Sets a certificate used for the device authentication
     *
     * @param deviceX509Certificate {@link CertificateToken}
     */
    public void setDeviceX509Certificate(CertificateToken deviceX509Certificate) {
        if (deviceX509Certificate == null) {
            this.deviceX509CertificateChain = null;
        } else {
            this.deviceX509CertificateChain = Collections.singletonList(deviceX509Certificate);
        }
    }

    /**
     * Sets a certificate chain used for the device authentication
     *
     * @param deviceX509CertificateChain an array of {@link CertificateToken}s
     */
    public void setDeviceX509CertificateChain(CertificateToken... deviceX509CertificateChain) {
        if (Utils.isArrayEmpty(deviceX509CertificateChain)) {
            this.deviceX509CertificateChain = null;
        } else {
            this.deviceX509CertificateChain = Arrays.asList(deviceX509CertificateChain);
        }
    }

    /**
     * Sets a certificate chain used for the device authentication
     *
     * @param deviceX509CertificateChain a list of {@link CertificateToken}s
     */
    public void setDeviceX509CertificateChain(List<CertificateToken> deviceX509CertificateChain) {
        this.deviceX509CertificateChain = deviceX509CertificateChain;
    }

    /**
     * Gets digest of the certificate used for the device authentication
     *
     * @return {@link Digest}
     */
    public Digest getDeviceX509CertificateThumbprint() {
        return deviceX509CertificateThumbprint;
    }

    /**
     * Sets digest of the certificate used for the device authentication
     *
     * @param deviceX509CertificateThumbprint {@link Digest}
     */
    public void setDeviceX509CertificateThumbprint(Digest deviceX509CertificateThumbprint) {
        this.deviceX509CertificateThumbprint = deviceX509CertificateThumbprint;
    }

    /**
     * Gets location of the certificate used for the device authentication
     *
     * @return {@link String}
     */
    public String getDeviceX509CertificateUrl() {
        return deviceX509CertificateUrl;
    }

    /**
     * Sets location of the certificate used for the device authentication
     *
     * @param deviceX509CertificateUrl {@link String}
     */
    public void setDeviceX509CertificateUrl(String deviceX509CertificateUrl) {
        this.deviceX509CertificateUrl = deviceX509CertificateUrl;
    }

    /**
     * Gets a "vct" claim value as defined by draft-ietf-oauth-sd-jwt-vc-13
     *
     * @return {@link String} the verifiable credentials type
     */
    public String getVerifiableCredentialsType() {
        return verifiableCredentialsType;
    }

    /**
     * Sets a "vct" claim value as defined by draft-ietf-oauth-sd-jwt-vc-13
     *
     * @param verifiableCredentialsType {@link String} the verifiable credentials type
     */
    public void setVerifiableCredentialsType(final String verifiableCredentialsType) {
        this.verifiableCredentialsType = verifiableCredentialsType;
    }

    /**
     * Gets a "vct#integrity" claim value as defined by draft-ietf-oauth-sd-jwt-vc-13
     *
     * @return {@link Digest} the verifiable credentials metadata integrity
     */
    public Digest getVerifiableCredentialsTypeIntegrity() {
        return verifiableCredentialsTypeIntegrity;
    }

    /**
     * Sets a "vct#integrity" claim value as defined by draft-ietf-oauth-sd-jwt-vc-13
     *
     * @param verifiableCredentialsTypeIntegrity {@link Digest} the verifiable credentials metadata integrity
     */
    public void setVerifiableCredentialsTypeIntegrity(final Digest verifiableCredentialsTypeIntegrity) {
        this.verifiableCredentialsTypeIntegrity = verifiableCredentialsTypeIntegrity;
    }

    /**
     * Sets the revocation, according to the ETSI TS 119 472-1 v1.2.1 definition,
     * that includes type, purpose, index and uri.
     * NOTE: when used, the properties are to be added within the "status" claim,
     * and not within the "status_list" child.
     *
     * @param type {@link String} type of the attestation revocation token (e.g. "TokenStatusList" for Token Status List
     *             as specified in IETF draft-ietf-oauth-revocation-list-13)
     * @param purpose {@link String} purpose of the revocation list
     * @param index integer representing an attestation identifier within the revocation
     * @param url {@link String} where the revocation can be accessed from
     */
    public void setStatusList(String type, String purpose, int index, String url) {
        setStatusList(new ETSITokenStatusList(type, purpose, index, url));
    }

    /**
     * Gets a catalogue of claims to be made selectively disclosable within the produced SD-JWT attestation.
     * When parameters are defined within the object, the computed hashes will be computed and
     * incorporated within "_sd" header parameter of the attestation Payload.
     * To provide the plain values on presentation, the disclosures shall be generated.
     *
     * @return {@link SDJWTClaimParameters}
     */
    public SDJWTClaimParameters selectivelyDisclosable() {
        return selectivelyDisclosableParameters;
    }

    /**
     * Gets a catalogue of claims to be mase non-selectively disclosable and
     * thus to be included within the SD-JWT attestation Payload in the plain form.
     *
     * @return {@link SDJWTClaimParameters}
     */
    public SDJWTClaimParameters nonSelectivelyDisclosable() {
        return nonSelectivelyDisclosableParameters;
    }

    @Override
    public String toString() {
        return "SDJWTPayloadParameters [" +
                "issuer='" + issuer + '\'' +
                ", selectivelyDisclosableParameters=" + selectivelyDisclosableParameters +
                ", nonSelectivelyDisclosableParameters=" + nonSelectivelyDisclosableParameters +
                ", verifiableCredentialsType='" + verifiableCredentialsType + '\'' +
                ", verifiableCredentialsIntegrity='" + verifiableCredentialsTypeIntegrity + '\'' +
                "] " + super.toString();
    }

}
