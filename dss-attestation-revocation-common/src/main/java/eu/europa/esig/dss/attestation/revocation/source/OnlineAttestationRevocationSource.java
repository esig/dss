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

import eu.europa.esig.dss.enumerations.AttestationRevocationOrigin;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.attestation.Attestation;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.attestation.revocation.validation.AttestationRevocationValidator;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Requests EAA Revocation for an EAA revocation verification using the online data loader.
 * This class uses a ServiceLoader to load a relevant validator based on the mechanism specified in the EAA's body.
 * To specify a list of supported mechanisms, please provide a list of corresponding classes in 
 * /resources/META-IN/services/eu.europa.esig.dss.attestation.revocation.validator.EAARevocationValidator file.
 *
 */
public class OnlineAttestationRevocationSource implements AttestationRevocationSource {

    private static final Logger LOG = LoggerFactory.getLogger(OnlineAttestationRevocationSource.class);

    /**
     * The component that allows to retrieve the data.
     */
    private DataLoader dataLoader;

    /**
     * The default constructor. A {@code NativeHTTPDataLoader} is created.
     */
    public OnlineAttestationRevocationSource() {
        dataLoader = new NativeHTTPDataLoader();
        LOG.trace("+OnlineEAARevocationSource with the default data loader.");
    }

    /**
     * This constructor allows to set a specific {@code DataLoader}.
     *
     * @param dataLoader
     *            the component that allows to retrieve the data.
     */
    public OnlineAttestationRevocationSource(final DataLoader dataLoader) {
        this.dataLoader = dataLoader;
        LOG.trace("+OnlineEAARevocationSource with the specific data loader.");
    }

    /**
     * Set the DataLoader to use for querying a revocation server.
     *
     * @param dataLoader
     *            the component that allows to retrieve a EAA Token Status List (TSL) response using HTTP.
     */
    public void setDataLoader(final DataLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    @Override
    public AttestationRevocationToken getAttestationRevocation(Attestation attestation) {
        Objects.requireNonNull(attestation, "EAA cannot be null!");
        Objects.requireNonNull(dataLoader, "DataLoader is not provided!");
        LOG.trace("--> OnlineEAARevocationSource queried for {}", attestation.getId());

        AttestationRevocationValidator validator = getValidator(attestation);
        if (validator != null) {
            try {
                AttestationRevocationToken attestationRevocationToken = validate(attestation, validator);
                if (attestationRevocationToken != null) {
                    return attestationRevocationToken;
                }
            } catch (Exception e) {
                LOG.warn("An error occurred on EAA revocation validation using the {} : {}", validator.getClass().getSimpleName(), e.getMessage());
            }
        }
        return null;
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
     * Performs validation of the {@code EAA} using the {@code validator}
     *
     * @param attestation {@link Attestation} to validate
     * @param validator {@link AttestationRevocationValidator} to perform validation process
     * @return {@link AttestationRevocationToken}
     */
    protected AttestationRevocationToken validate(Attestation attestation, AttestationRevocationValidator validator) {
        List<String> uris = validator.getUris(attestation);
        if (Utils.isCollectionEmpty(uris)) {
            return null;
        }

        int nbTries = uris.size();
        for (String uriLocation : uris) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to retrieve an EAA revocation from URL '{}'...", uriLocation);
            }
            nbTries--;

            try {
                byte[] bytes = dataLoader.get(uriLocation);
                if (Utils.isArrayEmpty(bytes)) {
                    LOG.warn("The server URL '{}' replied with en empty byte array!", bytes);
                    continue;
                }

                AttestationRevocationToken attestationRevocationToken = validator.validate(attestation, bytes);
                if (attestationRevocationToken == null) {
                    LOG.warn("The {} returned an empty token for the response retrieved from '{}' location",
                            validator.getClass().getSimpleName(), uriLocation);
                    continue;
                }
                attestationRevocationToken.setOrigin(AttestationRevocationOrigin.EXTERNAL);
                attestationRevocationToken.setSourceURL(uriLocation);
                attestationRevocationToken.setRelatedEAA(attestation);
                return attestationRevocationToken;

            } catch (Exception e) {
                if (nbTries == 0) {
                    throw new DSSExternalResourceException(String.format(
                            "Unable to retrieve EAA revocation response for EAA with Id '%s' from URL '%s'. Reason : %s",
                            attestation.getId(), uriLocation, e.getMessage()), e);
                } else {
                    LOG.warn("Unable to retrieve EAA revocation response with URL '{}' : {}", uriLocation, e.getMessage());
                }
            }
        }

        throw new IllegalStateException(String.format("Invalid state within OnlineEAARevocationSource " +
                "for a EAA revocation call with id '%s'", attestation.getId()));
    }

}
