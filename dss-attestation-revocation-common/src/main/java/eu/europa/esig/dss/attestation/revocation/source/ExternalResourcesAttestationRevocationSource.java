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
 * This class provides an EAA revocation source based on extracted EAA revocation documents
 *
 */
public class ExternalResourcesAttestationRevocationSource implements AttestationRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(ExternalResourcesAttestationRevocationSource.class);

    /** List of EAA revocation binaries */
    private final Set<AttestationRevocationTokenBinary> eaaRevocationBinaries = new HashSet<>();

    /** Cached map of EAAs and related revocation tokens */
    private final Map<String, AttestationRevocationToken> eaaRevocationTokens = new HashMap<>();

    /**
     * This constructor allows building of an EAA revocation source from an array of resource paths.
     *
     * @param paths
     *            paths to EAA revocation token documents
     */
    public ExternalResourcesAttestationRevocationSource(final String... paths) {
        for (final String pathItem : paths) {
            addEAARevocationDocument(getClass().getResourceAsStream(pathItem));
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
            addEAARevocationDocument(inputStream);
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
            addEAARevocationDocument(document.openStream());
        }
    }

    /**
     * This constructor allows building of a CRL source from an array of byte arrays.
     *
     * @param eaaBinaries
     *            an array of byte arrays
     */
    public ExternalResourcesAttestationRevocationSource(final byte[]... eaaBinaries) {
        for (final byte[] binaries : eaaBinaries) {
            addEAARevocationDocument(binaries);
        }
    }

    /**
     * Adds {@code inputStream} to the cached list of EAA revocation token binaries
     *
     * @param inputStream {@link InputStream} containing an EAA revocation token
     */
    protected void addEAARevocationDocument(InputStream inputStream) {
        addEAARevocationDocument(DSSUtils.toByteArray(inputStream));
    }

    /**
     * Adds {@code eaaBinaries} to the cached list of EAA revocation token binaries
     *
     * @param eaaBinaries byte array containing an EAA revocation token
     */
    protected void addEAARevocationDocument(byte[] eaaBinaries) {
        eaaRevocationBinaries.add(new AttestationRevocationTokenBinary(eaaBinaries));
    }

    @Override
    public AttestationRevocationToken getAttestationRevocation(Attestation attestation) {
        Objects.requireNonNull(attestation, "EAA cannot be null!");

        AttestationRevocationToken attestationRevocationToken = getCachedEAARevocationToken(attestation);
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
     * Gets a {@code EAARevocationToken} for the given {@code EAA} from a list of pre-processed tokens, when applicable
     *
     * @param attestation {@link Attestation}
     * @return {@link AttestationRevocationToken}
     */
    protected AttestationRevocationToken getCachedEAARevocationToken(Attestation attestation) {
        return eaaRevocationTokens.get(attestation.getId());
    }

    /**
     * Loads a relevant {@code EAARevocationValidator} for revocation revocation verification of the {@code attestation}
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
        LOG.warn("No supported EAA revocation claim has been found. EAA revocation request won't be performed.");
        return null;
    }

    /**
     * Validates the {@code EAA} across a provided list of EAA revocation binaries.
     * This method uses a subject name to identify a matching revocation token
     *
     * @param attestation {@link Attestation}
     * @param validator {@link AttestationRevocationValidator}
     * @return {@link AttestationRevocationToken}
     */
    protected AttestationRevocationToken validate(Attestation attestation, AttestationRevocationValidator validator) {
        List<String> uris = validator.getUris(attestation);
        for (AttestationRevocationTokenBinary revocationTokenBinary : eaaRevocationBinaries) {
            try {
                AttestationRevocationToken attestationRevocationToken = validator.validate(attestation, revocationTokenBinary.getBinaries());
                if (attestationRevocationToken != null && uris.contains(attestationRevocationToken.getSubject())) {
                    attestationRevocationToken.setOrigin(AttestationRevocationOrigin.EXTERNAL);
                    attestationRevocationToken.setSourceURL(attestationRevocationToken.getSubject());
                    attestationRevocationToken.setRelatedEAA(attestation);
                    eaaRevocationTokens.put(attestation.getId(), attestationRevocationToken);
                    return attestationRevocationToken;
                }
            } catch (Exception e) {
                // skip silently
            }
        }
        return null;
    }

}
