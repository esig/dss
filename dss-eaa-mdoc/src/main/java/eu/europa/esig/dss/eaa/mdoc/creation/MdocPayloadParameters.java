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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.eaa.common.creation.AbstractAttestationPayloadParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Provides a payload configuration for the ISO/IEC 18013-5 mdoc
 *
 */
public class MdocPayloadParameters extends AbstractAttestationPayloadParameters {

    /* MobileSecurityObject claims */

    /**
     * Version of the "MobileSecurityObject" structure.
     * Default : "1.0"
     */
    private String version = "1.0";

    /**
     * (Optional) A list of namespaces the device key may sign.
     */
    private List<String> keyAuthorizationsNamespaces;

    /**
     * (Optional) A map between namespaces and corresponding data element identifiers, the device key may sign.
     */
    private Map<String, List<String>> keyAuthorizationsDataElements;

    /**
     * (Optional) May contain extra info about the key. Positive integers for KeyInfo labels are RFU.
     * If application specific extensions are present, they shall use negative integers for the labels.
     */
    private Map<Integer, Object> keyInfoMap;

    /**
     * The document type of the document and shall be identical to the DocType element in the mdoc response.
     * Example: "org.iso.18013.5.1.mDL" for a document conformant to ISO/IEC 18013-5; or
     *          "org.iso.23220.1.mID" for a document conformant to ISO/IEC 23220-2.
     */
    private String docType;

    /**
     * Defines when the signature of the MSO is created.
     * NOTE: the value is taken from the corresponding signature parameters, if not provided explicitly.
     */
    private Date signed;

    /**
     * (Optional) Contains a date at which the issuing authority expects to re-sign the MSO
     * (and potentially update the elements).
     */
    private Date expectedUpdate;

    /**
     * (Optional) Contains an "identifier_list", as defined in ISO/IEC 18013-5 "12.3.6.4 Identifier list details".
     */
    private MdocIdentifierList identifierList;

    /**
     * Contains other optional selectively disclosable parameters
     */
    private MdocClaimParameters selectivelyDisclosableParameters;

    /**
     * Default constructor to instantiate ISO/IEC 18013-5 mdoc Payload parameters
     */
    public MdocPayloadParameters() {
        // empty
    }

    /**
     * Gets version of the "MobileSecurityObject" structure.
     *
     * @return {@link String}
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets version of the "MobileSecurityObject" structure.
     * Default : "1.0" (structure conformant to ISO/IEC 18013-5:2021)
     *
     * @param version {@link String}
     */
    public void setVersion(String version) {
        Objects.requireNonNull(version, "Version cannot be null!");
        this.version = version;
    }

    /**
     * Gets a list of namespaces the device key may sign.
     *
     * @return a list of namespaces
     */
    public List<String> getKeyAuthorizationsNamespaces() {
        return keyAuthorizationsNamespaces;
    }

    /**
     * Sets a list of namespaces the device key may sign.
     *
     * @param keyAuthorizationsNamespaces a list of {@link String} namespaces
     */
    public void setKeyAuthorizationsNamespaces(List<String> keyAuthorizationsNamespaces) {
        this.keyAuthorizationsNamespaces = keyAuthorizationsNamespaces;
    }

    /**
     * Gets a map between namespaces and corresponding data element identifiers, the device key may sign.
     *
     * @return a map between namespaces and data element identifiers
     */
    public Map<String, List<String>> getKeyAuthorizationsDataElements() {
        return keyAuthorizationsDataElements;
    }

    /**
     * (Optional) Sets a map between namespaces and corresponding data element identifiers, the device key may sign.
     *
     * @param keyAuthorizationsDataElements a map between namespaces and data element identifiers
     */
    public void setKeyAuthorizationsDataElements(Map<String, List<String>> keyAuthorizationsDataElements) {
        this.keyAuthorizationsDataElements = keyAuthorizationsDataElements;
    }

    /**
     * Gets a map containing extra information about the device key.
     *
     * @return a map between information identifiers and the corresponding data elements
     */
    public Map<Integer, Object> getKeyInfoMap() {
        return keyInfoMap;
    }

    /**
     * (Optional) Sets a map containing extra information about the device key.
     * Positive integers for KeyInfo labels are RFU. If application
     * specific extensions are present, they shall use negative integers for the labels.
     * NOTE: value of {@code Object} type is a subject to support by the implementation.
     * It is recommended to use an implementation of a {@code eu.europa.esig.dss.cbades.cbor.CBORObject} if applicable.
     *
     * @param keyInfoMap a map between information identifiers and the corresponding data elements
     */
    public void setKeyInfo(Map<Integer, Object> keyInfoMap) {
        this.keyInfoMap = keyInfoMap;
    }

    /**
     * Gets the document type.
     *
     * @return {@link String}
     */
    public String getDocType() {
        return docType;
    }

    /**
     * Sets the document type.
     * If not defined, the docType will be derived from the list of provided claims, if applicable.
     *
     * @param docType {@link String}
     */
    public void setDocType(String docType) {
        this.docType = docType;
    }

    /**
     * Gets the date when the EAA was signed
     *
     * @return {@link Date}
     */
    public Date getSigned() {
        return signed;
    }

    /**
     * Sets the date when the EAA was signed.
     * For the ISO/IEC 18013-5 mdoc this value corresponds to the ValidityInfo.signed date.
     *
     * @param signed {@link Date}
     */
    public void setSigned(Date signed) {
        this.signed = signed;
    }

    /**
     * Gets the date from which the EAA is valid
     *
     * @return {@link Date}
     */
    public Date getValidFrom() {
        return getNotBeforeDate();
    }

    /**
     * Sets the EAA notBefore date (technical validity start date).
     * For the ISO/IEC 18013-5 mdoc this value corresponds to the ValidityInfo.validFrom date.
     *
     * @param validFrom {@link Date}
     */
    public void setValidFrom(Date validFrom) {
        setNotBeforeDate(validFrom);
    }

    /**
     * Gets the date after which the EAA is no longer valid
     *
     * @return {@link Date}
     */
    public Date getValidUntil() {
        return getExpirationDate();
    }

    /**
     * Sets the EAA expiration date (technical validity end date).
     * For the ISO/IEC 18013-5 mdoc this value corresponds to the ValidityInfo.validFrom date.
     *
     * @param expirationDate {@link Date}
     */
    public void setValidUntil(Date expirationDate) {
        setExpirationDate(expirationDate);
    }

    /**
     * Gets the expected update date.
     *
     * @return {@link Date}
     */
    public Date getExpectedUpdate() {
        return expectedUpdate;
    }

    /**
     * Sets the date when EAA issuer expects the EAA or associated data to be updated.
     * For the ISO/IEC 18013-5 mdoc this value corresponds to the ValidityInfo.expectedUpdate date.
     *
     * @param expectedUpdate {@link Date}
     */
    public void setExpectedUpdate(Date expectedUpdate) {
        this.expectedUpdate = expectedUpdate;
    }

    /**
     * Gets the identifier_list
     *
     * @return {@link MdocIdentifierList}
     */
    public MdocIdentifierList getIdentifierList() {
        return identifierList;
    }

    /**
     * Sets the identifier_list
     *
     * @param identifierList {@link MdocIdentifierList}
     */
    public void setIdentifierList(MdocIdentifierList identifierList) {
        this.identifierList = identifierList;
    }

    /**
     * Sets the identifier_list, by specifying an index of the EAA and a status distribution URL
     *
     * @param identifier byte array representing an EAA identifier within the identifier_list
     * @param url {@link String} where the identifier_list can be accessed from
     */
    public void setIdentifierList(byte[] identifier, String url) {
        this.identifierList = new MdocIdentifierList(identifier, url);
    }

    /**
     * Sets the identifier_list, by specifying an index of the EAA and a status distribution URL
     *
     * @param identifier byte array representing an EAA identifier within the identifier_list
     * @param url {@link String} where the identifier_list can be accessed from
     * @param certificateToken {@link CertificateToken} containing the public key that signed or sealed
     *                         the top-level certificate in the x5chain element in the MSO revocation list structure
     */
    public void setIdentifierList(byte[] identifier, String url, CertificateToken certificateToken) {
        this.identifierList = new MdocIdentifierList(identifier, url, certificateToken);
    }

    /**
     * Gets parameters containing configuration of selectively disclosable claims
     *
     * @return {@link MdocClaimParameters}
     */
    public MdocClaimParameters selectivelyDisclosable() {
        if (selectivelyDisclosableParameters == null) {
            selectivelyDisclosableParameters = new MdocClaimParameters();
        }
        return selectivelyDisclosableParameters;
    }

    @Override
    public String toString() {
        return "MdocEAAPayloadParameters [" +
                "version='" + version + '\'' +
                ", keyAuthorizationsNamespaces=" + keyAuthorizationsNamespaces +
                ", keyAuthorizationsDataElements=" + keyAuthorizationsDataElements +
                ", keyInfoMap=" + keyInfoMap +
                ", docType='" + docType + '\'' +
                ", signed=" + signed +
                ", expectedUpdate=" + expectedUpdate +
                ", selectivelyDisclosableParameters=" + selectivelyDisclosableParameters +
                "] " + super.toString();
    }

}
