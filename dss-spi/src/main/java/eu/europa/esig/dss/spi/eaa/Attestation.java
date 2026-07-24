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
package eu.europa.esig.dss.spi.eaa;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.model.eaa.DisclosureValidation;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.util.List;

/**
 * This class represents a presentation of Electronic Attestation of Attributes
 *
 */
public interface Attestation extends IdentifierBasedObject {

    /**
     * Returns a name of the presentation of Electronic Attestation of Attributes document, when present
     *
     * @return {@link String}
     */
    String getFilename();

    /**
     * Gets a list of signatures used to issue the Electronic Attestation of Attributes
     *
     * @return a list of {@link AdvancedSignature}s
     */
    List<AdvancedSignature> getSignatures();

    /**
     * Gets the type of the Electronic Attestation of Attributes
     *
     * @return {@link AttestationFormat}
     */
    AttestationFormat getEAAType();

    /**
     * Gets a list of validation results performed on the selectively disclosable claims
     *
     * @return list of {@link DisclosureValidation}
     */
    List<DisclosureValidation> getDisclosureValidations();

    /**
     * Gets key binding signature, when present
     *
     * @return {@link AdvancedSignature}
     */
    AdvancedSignature getKeyBindingSignature();

    /**
     * Gets key binding payload, when present
     *
     * @return {@link KeyBindingSignaturePayload}
     */
    KeyBindingSignaturePayload getKeyBindingSignaturePayload();

    /**
     * Gets the certificate source containing a public key or certificate representation of the device holder
     *
     * @return {@link CertificateSource}
     */
    CertificateSource getDeviceKeyCertificateSource();

    /**
     * Gets a clear payload of the Electronic Attestation of Attributes
     *
     * @return {@link AttestationPayload}
     */
    AttestationPayload getPayload();

    /**
     * Gets DigestAlgorithm used for selective disclosures hashes computation
     *
     * @return {@link DigestAlgorithm}
     */
    DigestAlgorithm getSelectiveDisclosuresDigestAlgorithm();

    /**
     * This method returns the DSS unique id. It allows to unambiguously identify each token.
     *
     * @return {@link String} unique Id
     */
    String getId();

}
