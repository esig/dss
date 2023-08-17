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
package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.FileNameBuilder;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Signature;
import java.util.Objects;

/**
 * The abstract class containing the main methods for a signature creation/extension
 *
 * @param <SP> SignatureParameters
 * @param <TP> TimestampParameters
 */
@SuppressWarnings("serial")
public abstract class AbstractSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters>
        implements DocumentSignatureService<SP, TP> {

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    private static final Logger LOG = LoggerFactory.getLogger(AbstractSignatureService.class);

    /** The CertificateVerifier used for a certificate chain validation */
    protected final CertificateVerifier certificateVerifier;

    /** The TSPSource to use for timestamp requests */
    protected TSPSource tspSource;

    /**
     * To construct a signature service the <code>CertificateVerifier</code> must be set and cannot be null.
     *
     * @param certificateVerifier
     *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
     *            in the context of a signature.
     */
    protected AbstractSignatureService(final CertificateVerifier certificateVerifier) {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier cannot be null !");
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public void setTspSource(final TSPSource tspSource) {
        this.tspSource = tspSource;
    }

    /**
     * This method raises an exception if the signing rules forbid the use the certificate.
     *
     * @param parameters
     *            set of driving signing parameters
     */
    protected void assertSigningCertificateValid(final AbstractSignatureParameters<?> parameters) {
        final CertificateToken signingCertificate = parameters.getSigningCertificate();
        if (signingCertificate == null) {
            if (parameters.isGenerateTBSWithoutCertificate()) {
                return;
            } else {
                throw new IllegalArgumentException("Signing Certificate is not defined! " +
                        "Set signing certificate or use method setGenerateTBSWithoutCertificate(true).");
            }
        }

        final SignatureRequirementsChecker signatureRequirementsChecker = new SignatureRequirementsChecker(
                certificateVerifier, parameters);
        signatureRequirementsChecker.assertSigningCertificateIsValid(signingCertificate);
    }

    /**
     * This method ensures the provided {@code signatureValue} has the expected {@code targetSignatureAlgorithm}
     *
     * @param targetSignatureAlgorithm
     *            {@link SignatureAlgorithm} to convert the signatureValue to
     * @param signatureValue
     *            {@link SignatureValue} obtained from a signing token
     * @return {@link SignatureValue} with the defined {@code SignatureAlgorithm} in parameters
     */
    protected SignatureValue ensureSignatureValue(SignatureAlgorithm targetSignatureAlgorithm, SignatureValue signatureValue) {
        return new SignatureValueChecker().ensureSignatureValue(signatureValue, targetSignatureAlgorithm);
    }

    /**
     * Generates and returns a final name for the document to create
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param operation {@link SigningOperation} the performed signing operation
     * @param level {@link SignatureLevel} the final signature level
     * @param packaging {@link SignaturePackaging} the used packaging to create original signature
     * @param containerMimeType {@link MimeType} the expected mimeType
     * @return {@link String} the document filename
     */
    protected String getFinalDocumentName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level,
                                          SignaturePackaging packaging, MimeType containerMimeType) {
        return new FileNameBuilder().setOriginalFilename(originalFile.getName()).setSigningOperation(operation)
                .setSignatureLevel(level).setSignaturePackaging(packaging).setMimeType(containerMimeType).build();
    }

    /**
     * Returns the final name for the document to create
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param operation {@link SigningOperation} the performed signing operation
     * @return {@link String} the document filename
     */
    protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation) {
        return getFinalFileName(originalFile, operation, null);
    }

    /**
     * Returns the final name for the document to create
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param operation {@link SigningOperation} the performed signing operation
     * @param level {@link SignatureLevel} the final signature level
     * @return {@link String} the document filename
     */
    protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level) {
        return getFinalDocumentName(originalFile, operation, level, null);
    }


    /**
     * Returns the final name for the document to create
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param operation {@link SigningOperation} the performed signing operation
     * @param level {@link SignatureLevel} the final signature level
     * @param packaging {@link SignaturePackaging} the used packaging to create original signature
     * @return {@link String} the document filename
     */
    protected String getFinalFileName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level,
                                      SignaturePackaging packaging) {
        return getFinalDocumentName(originalFile, operation, level, packaging, null);
    }

    /**
     * Generates and returns a final name for the document to create
     *
     * @param originalFile {@link DSSDocument} original signed/extended document
     * @param operation {@link SigningOperation} the performed signing operation
     * @param level {@link SignatureLevel} the final signature level
     * @param containerMimeType {@link MimeType} the expected mimeType
     * @return {@link String} the document filename
     */
    protected String getFinalDocumentName(DSSDocument originalFile, SigningOperation operation, SignatureLevel level,
                                          MimeType containerMimeType) {
        return getFinalDocumentName(originalFile, operation, level, null, containerMimeType);
    }

    @Override
    public DSSDocument timestamp(DSSDocument toTimestampDocument, TP parameters) {
        throw new UnsupportedOperationException("Unsupported operation for this file format");
    }

    @Override
    public boolean isValidSignatureValue(ToBeSigned toBeSigned, SignatureValue signatureValue, CertificateToken signingCertificate) {
        Objects.requireNonNull(toBeSigned, "ToBeSigned cannot be null!");
        Objects.requireNonNull(signatureValue, "SignatureValue cannot be null!");
        Objects.requireNonNull(signingCertificate, "CertificateToken cannot be null!");

        try {
            Signature signature = Signature.getInstance(signatureValue.getAlgorithm().getJCEId(), DSSSecurityProvider.getSecurityProviderName());
            signature.initVerify(signingCertificate.getPublicKey());
            signature.update(toBeSigned.getBytes());
            return signature.verify(signatureValue.getValue());
        } catch (GeneralSecurityException | IllegalStateException e) { // IllegalStateException because of org.bouncycastle.jcajce.provider.asymmetric.edec.SignatureSpi
            LOG.error("Unable to verify the signature value : {}", e.getMessage());
            return false;
        }
    }

}

