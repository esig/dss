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
package eu.europa.esig.dss.attestation.revocation.source;

import eu.europa.esig.dss.attestation.revocation.validation.AttestationRevocationValidator;
import eu.europa.esig.dss.enumerations.AttestationRevocationOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationTokenBinary;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.Set;

/**
 * This class provides an attestation revocation source based on extracted attestation revocation documents
 *
 */
public class ExternalResourcesAttestationRevocationSource implements AttestationRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalResourcesAttestationRevocationSource.class);

    /** List of attestation revocation binaries */
    private final Set<AttestationRevocationTokenBinary> attestationRevocationBinaries = new HashSet<>();

    /** Cached map of attestations and related revocation tokens */
    private final Map<String, AttestationRevocationToken> attestationRevocationTokens = new HashMap<>();

    /**
     * This constructor allows building of an attestation revocation source from an array of resource paths.
     *
     * @param paths
     *            paths to attestation revocation token documents
     */
    public ExternalResourcesAttestationRevocationSource(final String... paths) {
        for (final String pathItem : paths) {
            addAttestationRevocationDocument(getClass().getResourceAsStream(pathItem));
        }
    }

    /**
     * This constructor allows building of a CRL source from an array of <code>InputStream</code>s.
     *
     * @param inputStreams
     *            an array of <code>InputStream</code>s
     */
    public ExternalResourcesAttestationRevocationSource(final InputStream... inputStreams) {
        for (final InputStream inputStream : inputStreams) {
            addAttestationRevocationDocument(inputStream);
        }
    }

    /**
     * This constructor allows building of a CRL source from an array of <code>DSSDocument</code>s.
     *
     * @param dssDocuments
     *            an array of <code>DSSDocument</code>s
     */
    public ExternalResourcesAttestationRevocationSource(final DSSDocument... dssDocuments) {
        for (final DSSDocument document : dssDocuments) {
            addAttestationRevocationDocument(document.openStream());
        }
    }

    /**
     * This constructor allows building of a CRL source from an array of byte arrays.
     *
     * @param attestationBinaries
     *            an array of byte arrays
     */
    public ExternalResourcesAttestationRevocationSource(final byte[]... attestationBinaries) {
        for (final byte[] binaries : attestationBinaries) {
            addAttestationRevocationDocument(binaries);
        }
    }

    /**
     * Adds {@code inputStream} to the cached list of attestation revocation token binaries
     *
     * @param inputStream {@link InputStream} containing an attestation revocation token
     */
    protected void addAttestationRevocationDocument(InputStream inputStream) {
        addAttestationRevocationDocument(DSSUtils.toByteArray(inputStream));
    }

    /**
     * Adds {@code attestationBinaries} to the cached list of attestation revocation token binaries
     *
     * @param attestationBinaries byte array containing an attestation revocation token
     */
    protected void addAttestationRevocationDocument(byte[] attestationBinaries) {
        attestationRevocationBinaries.add(new AttestationRevocationTokenBinary(attestationBinaries));
    }

    @Override
    public AttestationRevocationToken getAttestationRevocation(Attestation attestation) {
        Objects.requireNonNull(attestation, "Attestation cannot be null!");

        AttestationRevocationToken attestationRevocationToken = getCachedAttestationRevocationToken(attestation);
        if (attestationRevocationToken != null) {
            return attestationRevocationToken;
        }

        AttestationRevocationValidator validator = getValidator(attestation);
        if (validator != null) {
            attestationRevocationToken = validate(attestation, validator);
        }
        return attestationRevocationToken;
    }

    /**
     * Gets a {@code AttestationRevocationToken} for the given {@code Attestation} from a list of pre-processed tokens, when applicable
     *
     * @param attestation {@link Attestation}
     * @return {@link AttestationRevocationToken}
     */
    protected AttestationRevocationToken getCachedAttestationRevocationToken(Attestation attestation) {
        return attestationRevocationTokens.get(attestation.getId());
    }

    /**
     * Loads a relevant {@code AttestationRevocationValidator} for revocation status verification of the {@code attestation}
     *
     * @param attestation {@link Attestation} to be verified
     * @return {@link AttestationRevocationValidator}
     */
    protected AttestationRevocationValidator getValidator(Attestation attestation) {
        ServiceLoader<AttestationRevocationValidator> loader = ServiceLoader.load(AttestationRevocationValidator.class);
        Iterator<AttestationRevocationValidator> validatorOptions = loader.iterator();

        if (validatorOptions.hasNext()) {
            for (AttestationRevocationValidator validator : loader) {
                if (validator.isSupported(attestation)) {
                    return validator;
                }
            }
        }
        LOG.warn("No supported attestation revocation claim has been found. Attestation revocation request won't be performed.");
        return null;
    }

    /**
     * Validates the {@code Attestation} across a provided list of attestation revocation binaries.
     * This method uses a subject name to identify a matching revocation token
     *
     * @param attestation {@link Attestation}
     * @param validator {@link AttestationRevocationValidator}
     * @return {@link AttestationRevocationToken}
     */
    protected AttestationRevocationToken validate(Attestation attestation, AttestationRevocationValidator validator) {
        List<String> uris = validator.getUris(attestation);
        for (AttestationRevocationTokenBinary revocationTokenBinary : attestationRevocationBinaries) {
            try {
                AttestationRevocationToken attestationRevocationToken = validator.validate(attestation, revocationTokenBinary.getBinaries());
                if (attestationRevocationToken != null && uris.contains(attestationRevocationToken.getSubject())) {
                    attestationRevocationToken.setOrigin(AttestationRevocationOrigin.EXTERNAL);
                    attestationRevocationToken.setSourceURL(attestationRevocationToken.getSubject());
                    attestationRevocationToken.setRelatedAttestation(attestation);
                    attestationRevocationTokens.put(attestation.getId(), attestationRevocationToken);
                    return attestationRevocationToken;
                }
            } catch (Exception e) {
                // skip silently
            }
        }
        return null;
    }

}
