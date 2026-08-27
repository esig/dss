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
package eu.europa.esig.dss.jades.lote;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParametersBuilder;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.Objects;

/**
 * Helper class to build signature parameters for signing a TS 119 602 JSON List of Trusted Entities.
 * To create a pre-configured parameters, please call the {@link #build()} method.
 * Please note that the {@link #build()} method does not verify the validity of the submitted file's structure.
 * To verify conformance of a LoTE to the specification, please call {@link #assertConfigurationIsValid()} method.
 *
 */
public class JsonListOfTrustedEntitiesSignatureParametersBuilder extends AbstractSignatureParametersBuilder<JAdESSignatureParameters> {

    /**
     * The JSON List of Trusted Entities document
     */
    private final DSSDocument loteJsonDocument;

    /**
     * Default constructor.
     * When used, the {@link #assertConfigurationIsValid} is not supported.
     * Please use a constructor with a JSON LoTE document provided if verification of the document conformity is required.
     *
     * @param signingCertificate {@link CertificateToken} representing a certificate associated with the signing key
     */
    public JsonListOfTrustedEntitiesSignatureParametersBuilder(CertificateToken signingCertificate) {
        this(signingCertificate, null);
    }

    /**
     * Constructor supporting verification of the JSON List of Trusted Entities document
     *
     * @param signingCertificate {@link CertificateToken} representing a certificate associated with the signing key
     * @param loteJsonDocument {@link DSSDocument} representing a document to be signed
     */
    public JsonListOfTrustedEntitiesSignatureParametersBuilder(CertificateToken signingCertificate, DSSDocument loteJsonDocument) {
        super(signingCertificate);
        this.loteJsonDocument = loteJsonDocument;
    }

    @Override
    protected JAdESSignatureParameters initParameters() {
        return new JAdESSignatureParameters();
    }

    @Override
    public JAdESSignatureParameters build() {
        final JAdESSignatureParameters signatureParameters = super.build();

        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

        return signatureParameters;
    }

    /**
     * This method helps to determine whether the chosen signature parameters builders is applicable to the given document.
     * Thus, it verifies whether the provided document representing the JSON List of Trusted Entities is conformant to the definition
     * and the target version.
     * NOTE: this method requires 'specs-lote-json' module.
     *
     * @throws IllegalInputException if the provided JSON List of Trusted Entities has invalid structure
     * @throws DSSException is other error occurred during the processing
     */
    public void assertConfigurationIsValid() throws IllegalInputException {
        Objects.requireNonNull(loteJsonDocument, "List of Trusted Entities document is not provided or null!");

        List<String> errors;
        try {
            errors = JAdESListOfTrustedEntitiesUtils.validateUnsignedLOTE(loteJsonDocument);
        } catch (Exception e) {
            throw new DSSException(String.format("An error occurred on JSON List of Trusted Entities validation : %s",
                    e.getMessage()), e);
        }
        if (Utils.isCollectionNotEmpty(errors)) {
            throw new IllegalInputException(String.format(
                    "JSON List of Trusted Entities failed the validation : %s", Utils.joinStrings(errors, "; ")));
        }
    }

}
