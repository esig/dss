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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class creates an instance of {@code ValidationPolicy}
 *
 */
public class ValidationPolicyLoader {

    /** Validation policy document, when provided */
    private final ValidationPolicy validationPolicy;

    /** Map of cryptographic suite documents and their applicability scopes */
    private final Map<CryptographicSuite, List<ContextAndSubContext>> cryptographicSuitesMap = new HashMap<>();

    /**
     * Empty constructor
     */
    protected ValidationPolicyLoader() {
        this(null);
    }

    /**
     * Constructor to create a {@code ValidationPolicyFactory} using a custom validation policy
     *
     * @param validationPolicy {@link ValidationPolicy} to use
     */
    protected ValidationPolicyLoader(ValidationPolicy validationPolicy) {
        this.validationPolicy = validationPolicy;
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a default validation policy
     *
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromDefaultValidationPolicy() {
        return fromValidationPolicy(loadDefaultPolicy());
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicy {@link File} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(DSSDocument validationPolicy) {
        Objects.requireNonNull(validationPolicy, "Validation policy document cannot be null!");
        return fromValidationPolicy(loadPolicy(validationPolicy));
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy {@code InputStream}
     *
     * @param validationPolicyStream {@link InputStream} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(InputStream validationPolicyStream) {
        Objects.requireNonNull(validationPolicyStream, "Validation policy stream cannot be null!");
        return fromValidationPolicy(new InMemoryDocument(validationPolicyStream));
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicyFile {@link File} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(File validationPolicyFile) {
        Objects.requireNonNull(validationPolicyFile, "Validation policy file cannot be null!");
        return fromValidationPolicy(new FileDocument(validationPolicyFile));
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicyFilePath
     *           {@link String} path to the validation policy file, located against
     *           the classpath (getClass().getResourceAsStream), and NOT the filesystem
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(String validationPolicyFilePath) {
        Objects.requireNonNull(validationPolicyFilePath, "Validation policy file path cannot be null!");
        try (InputStream is = ValidationPolicyLoader.class.getResourceAsStream(validationPolicyFilePath)) {
            return fromValidationPolicy(is);
        } catch (IOException e) {
            throw new IllegalInputException(String.format( "Unable to load a cryptographic suite from path '%s'. " +
                    "Reason : %s", validationPolicyFilePath, e.getMessage()), e);
        }
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy
     *
     * @param validationPolicy {@link ValidationPolicy}
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(ValidationPolicy validationPolicy) {
        Objects.requireNonNull(validationPolicy, "Validation policy cannot be null!");
        return new ValidationPolicyLoader(validationPolicy);
    }

    /**
     * Sets a default cryptographic suite for the given Context and SubContext.
     * This method will load the first available cryptographic suite.
     * DSS provides two modules with implementations, namely 'dss-policy-crypto-xml' and 'dss-policy-crypto-json'.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuite() {
        return withDefaultCryptographicSuiteForContext(null);
    }

    /**
     * Sets a global cryptographic suite {@code DSSDocument}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #withCryptographicSuiteForContext} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(DSSDocument cryptographicSuite) {
        return withCryptographicSuiteForContext(cryptographicSuite, null);
    }

    /**
     * Sets a global cryptographic suite {@code InputStream}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #withCryptographicSuiteForContext} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(InputStream cryptographicSuiteIS) {
        return withCryptographicSuiteForContext(cryptographicSuiteIS, null);
    }

    /**
     * Sets a global cryptographic suite {@code File}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #withCryptographicSuiteForContext} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(File cryptographicSuiteFile) {
        return withCryptographicSuiteForContext(cryptographicSuiteFile, null);
    }

    /**
     * Sets a global cryptographic suite file.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #withCryptographicSuiteForContext} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteFilePath
     *           {@link String} path to the cryptographic suite file, located against
     *           the classpath (getClass().getResourceAsStream), and NOT the filesystem
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(String cryptographicSuiteFilePath) {
        return withCryptographicSuiteForContext(cryptographicSuiteFilePath, null);
    }

    /**
     * Sets a global cryptographic suite.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #withCryptographicSuiteForContext} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(CryptographicSuite cryptographicSuite) {
        return withCryptographicSuiteForContext(cryptographicSuite, null);
    }

    /**
     * Sets a default cryptographic suite for the given Context and SubContext.
     * This method will load the first available cryptographic suite.
     * DSS provides two modules with implementations, namely 'dss-policy-crypto-xml' and 'dss-policy-crypto-json'.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuiteForContext(Context context) {
        return withDefaultCryptographicSuiteForContext(context, null);
    }

    /**
     * Sets a cryptographic suite {@code DSSDocument} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(DSSDocument cryptographicSuite, Context context) {
        return withCryptographicSuiteForContext(cryptographicSuite, context, null);
    }

    /**
     * Sets a cryptographic suite {@code InputStream} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(InputStream cryptographicSuiteIS, Context context) {
        return withCryptographicSuiteForContext(cryptographicSuiteIS, context, null);
    }

    /**
     * Sets a cryptographic suite {@code File} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(File cryptographicSuiteFile, Context context) {
        return withCryptographicSuiteForContext(cryptographicSuiteFile, context, null);
    }

    /**
     * Sets a cryptographic suite file for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFilePath
     *           {@link String} path to the cryptographic suite file, located against
     *           the classpath (getClass().getResourceAsStream), and NOT the filesystem
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(String cryptographicSuiteFilePath, Context context) {
        return withCryptographicSuiteForContext(cryptographicSuiteFilePath, context, null);
    }

    /**
     * Sets a cryptographic suite for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param context {@link Context}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(CryptographicSuite cryptographicSuite, Context context) {
        return withCryptographicSuiteForContext(cryptographicSuite, context, null);
    }

    /**
     * Sets a default cryptographic suite for the given Context and SubContext.
     * This method will load the first available cryptographic suite.
     * DSS provides two modules with implementations, namely 'dss-policy-crypto-xml' and 'dss-policy-crypto-json'.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuiteForContext(Context context, SubContext subContext) {
        if (Context.EVIDENCE_RECORD == context && subContext != null) {
            throw new IllegalArgumentException("Please use a NULL SubContext for the Context.EVIDENCE_RECORD or " +
                    "use #withDefaultCryptographicSuiteForContext(cryptographicSuite, context) method.");
        }
        return withCryptographicSuiteForContext(loadDefaultCryptographicSuite(), context, subContext);
    }

    /**
     * Sets a cryptographic suite {@code DSSDocument} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(DSSDocument cryptographicSuite, Context context, SubContext subContext) {
        Objects.requireNonNull(cryptographicSuite, "Cryptographic suite document cannot be null!");
        return withCryptographicSuiteForContext(loadCryptographicSuite(cryptographicSuite), context, subContext);
    }

    /**
     * Sets a cryptographic suite {@code InputStream} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(InputStream cryptographicSuiteIS, Context context, SubContext subContext) {
        Objects.requireNonNull(cryptographicSuiteIS, "Cryptographic suite stream cannot be null!");
        return withCryptographicSuiteForContext(new InMemoryDocument(cryptographicSuiteIS), context, subContext);
    }

    /**
     * Sets a cryptographic suite {@code File} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(File cryptographicSuiteFile, Context context, SubContext subContext) {
        Objects.requireNonNull(cryptographicSuiteFile, "Cryptographic suite file cannot be null!");
        return withCryptographicSuiteForContext(new FileDocument(cryptographicSuiteFile), context, subContext);
    }

    /**
     * Sets a cryptographic suite file for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFilePath
     *           {@link String} path to the cryptographic suite file, located against
     *           the classpath (getClass().getResourceAsStream), and NOT the filesystem
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(String cryptographicSuiteFilePath, Context context, SubContext subContext) {
        Objects.requireNonNull(cryptographicSuiteFilePath, "Cryptographic suite file path cannot be null!");
        try (InputStream is = getClass().getResourceAsStream(cryptographicSuiteFilePath)) {
            return withCryptographicSuiteForContext(is, context, subContext);
        } catch (IOException e) {
            throw new IllegalInputException(String.format( "Unable to load a cryptographic suite from path '%s'. " +
                    "Reason : %s", cryptographicSuiteFilePath, e.getMessage()), e);
        }
    }

    /**
     * Sets a cryptographic suite for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link CryptographicSuite}
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @return {@link ValidationPolicyLoader}
     */
    public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(CryptographicSuite cryptographicSuite, Context context, SubContext subContext) {
        Objects.requireNonNull(cryptographicSuite, "Cryptographic suite cannot be null!");
        cryptographicSuitesMap.computeIfAbsent(cryptographicSuite, k -> new ArrayList<>())
                .add(new ContextAndSubContext(context, subContext));
        return new ValidationPolicyLoaderWithCryptoSuite(this, cryptographicSuite);
    }

    /**
     * Builds a {@code ValidationPolicy}
     *
     * @return {@link ValidationPolicy}
     */
    public ValidationPolicy create() {
        if (Utils.isMapEmpty(cryptographicSuitesMap)) {
            return validationPolicy;
        }

        ValidationPolicyWithCryptographicSuite validationPolicyWithCryptographicSuite =
                new ValidationPolicyWithCryptographicSuite(validationPolicy);
        for (Map.Entry<CryptographicSuite, List<ContextAndSubContext>> entry : cryptographicSuitesMap.entrySet()) {
            CryptographicSuite cryptographicSuite = entry.getKey();
            for (ContextAndSubContext scope : entry.getValue()) {
                if (scope == null) {
                    validationPolicyWithCryptographicSuite.setCryptographicSuite(cryptographicSuite);
                } else {
                    validationPolicyWithCryptographicSuite.setCryptographicSuite(cryptographicSuite, scope.getContext(), scope.getSubContext());
                }
            }
        }
        return validationPolicyWithCryptographicSuite;
    }

    /**
     * Loads a default validation policy
     *
     * @return {@link ValidationPolicy}
     */
    private static ValidationPolicy loadDefaultPolicy() {
        ServiceLoader<ValidationPolicyFactory> loader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> factoryOptions = loader.iterator();

        if (factoryOptions.hasNext()) {
            // Loads the first one
            return factoryOptions.next().loadDefaultValidationPolicy();
        }
        throw new UnsupportedOperationException("No ValidationPolicyFactory has been found! " +
                "Please add 'dss-policy-jaxb' module to the classpath or create your own implementation.");
    }

    /**
     * Loads a validation policy from the given {@code DSSDocument}
     *
     * @param validationPolicyDocument {@link DSSDocument} representing the validation policy document
     * @return {@link ValidationPolicy}
     */
    private static ValidationPolicy loadPolicy(DSSDocument validationPolicyDocument) {
        ServiceLoader<ValidationPolicyFactory> loader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> factoryOptions = loader.iterator();

        while (factoryOptions.hasNext()) {
            ValidationPolicyFactory factory = factoryOptions.next();
            if (factory.isSupported(validationPolicyDocument)) {
                return factory.loadValidationPolicy(validationPolicyDocument);
            }
        }
        throw new UnsupportedOperationException("The validation policy is not valid or no suitable ValidationPolicyFactory has been found! " +
                "Please ensure the provided policy file is valid and 'dss-policy-jaxb' module is added to the classpath or " +
                "create your own implementation for a custom policy.");
    }

    /**
     * Loads a default cryptographic suite
     *
     * @return {@link CryptographicSuite}
     */
    private static CryptographicSuite loadDefaultCryptographicSuite() {
        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        if (factoryOptions.hasNext()) {
            // Loads the first one
            return factoryOptions.next().loadDefaultCryptographicSuite();
        }
        throw new UnsupportedOperationException("No ValidationPolicyFactory has been found! " +
                "Please add 'dss-policy-jaxb' module to the classpath or create your own implementation.");
    }

    /**
     * Loads a cryptographic suite from the given {@code cryptographicSuiteDocument}
     *
     * @param cryptographicSuiteDocument {@link DSSDocument}
     * @return {@link CryptographicSuite}
     */
    private static CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument) {
        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        while (factoryOptions.hasNext()) {
            CryptographicSuiteFactory factory = factoryOptions.next();
            if (factory.isSupported(cryptographicSuiteDocument)) {
                return factory.loadCryptographicSuite(cryptographicSuiteDocument);
            }
        }
        throw new UnsupportedOperationException("The cryptographic suite file is not valid or no suitable CryptographicSuiteFactory has been found! " +
                "Please ensure the provided policy file is valid and 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' module is added to the classpath or " +
                "create your own implementation for a custom cryptographic suite policy.");
    }

    /**
     * This class provides a user-friendly configuration of the execution levels for the last set cryptographic suite.
     * For generic methods inherited from {@code ValidationPolicyLoader}, the execution is propagated to
     * the original instance of the loader.
     */
    public static class ValidationPolicyLoaderWithCryptoSuite extends ValidationPolicyLoader {

        /** Current ValidationPolicyLoader */
        private final ValidationPolicyLoader validationPolicyLoader;

        /** The current added cryptographic suite */
        private final CryptographicSuite cryptographicSuite;

        /**
         * Constructor to create a {@code ValidationPolicyFactory} using a custom validation policy
         *
         * @param validationPolicyLoader {@link ValidationPolicyLoader}
         * @param cryptographicSuite {@link CryptographicSuite}
         */
        protected ValidationPolicyLoaderWithCryptoSuite(final ValidationPolicyLoader validationPolicyLoader,
                                                        final CryptographicSuite cryptographicSuite) {
            this.validationPolicyLoader = validationPolicyLoader;
            this.cryptographicSuite = cryptographicSuite;
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuite() {
            return validationPolicyLoader.withDefaultCryptographicSuite();
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(DSSDocument cryptographicSuite) {
            return validationPolicyLoader.withCryptographicSuite(cryptographicSuite);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(InputStream cryptographicSuiteIS) {
            return validationPolicyLoader.withCryptographicSuite(cryptographicSuiteIS);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(File cryptographicSuiteFile) {
            return validationPolicyLoader.withCryptographicSuite(cryptographicSuiteFile);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(String cryptographicSuiteFilePath) {
            return validationPolicyLoader.withCryptographicSuite(cryptographicSuiteFilePath);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuite(CryptographicSuite cryptographicSuite) {
            return validationPolicyLoader.withCryptographicSuite(cryptographicSuite);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuiteForContext(Context context) {
            return validationPolicyLoader.withDefaultCryptographicSuiteForContext(context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(DSSDocument cryptographicSuite, Context context) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuite, context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(InputStream cryptographicSuiteIS, Context context) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteIS, context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(File cryptographicSuiteFile, Context context) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteFile, context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(String cryptographicSuiteFilePath, Context context) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteFilePath, context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(CryptographicSuite cryptographicSuite, Context context) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuite, context);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withDefaultCryptographicSuiteForContext(Context context, SubContext subContext) {
            return validationPolicyLoader.withDefaultCryptographicSuiteForContext(context, subContext);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(DSSDocument cryptographicSuite, Context context, SubContext subContext) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuite, context, subContext);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(InputStream cryptographicSuiteIS, Context context, SubContext subContext) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteIS, context, subContext);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(File cryptographicSuiteFile, Context context, SubContext subContext) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteFile, context, subContext);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(String cryptographicSuiteFilePath, Context context, SubContext subContext) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuiteFilePath, context, subContext);
        }

        @Override
        public ValidationPolicyLoaderWithCryptoSuite withCryptographicSuiteForContext(CryptographicSuite cryptographicSuite, Context context, SubContext subContext) {
            return validationPolicyLoader.withCryptographicSuiteForContext(cryptographicSuite, context, subContext);
        }

        @Override
        public ValidationPolicy create() {
            return validationPolicyLoader.create();
        }

        /**
         * Sets the global execution level for the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andLevel(Level level) {
            cryptographicSuite.setLevel(level);
            return this;
        }

        /**
         * Sets the execution level for acceptable digest algorithms check of the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andAcceptableDigestAlgorithmsLevel(Level level) {
            cryptographicSuite.setAcceptableDigestAlgorithmsLevel(level);
            return this;
        }

        /**
         * Sets the execution level for acceptable encryption algorithms check of the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andAcceptableEncryptionAlgorithmsLevel(Level level) {
            cryptographicSuite.setAcceptableEncryptionAlgorithmsLevel(level);
            return this;
        }

        /**
         * Sets the execution level for acceptable minimum key sizes of encryption algorithms check of
         * the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andAcceptableEncryptionAlgorithmsMiniKeySizeLevel(Level level) {
            cryptographicSuite.setAcceptableEncryptionAlgorithmsMiniKeySizeLevel(level);
            return this;
        }

        /**
         * Sets the execution level for the expiration of the cryptographic algorithms check of
         * the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andAlgorithmsExpirationDateLevel(Level level) {
            cryptographicSuite.setAlgorithmsExpirationDateLevel(level);
            return this;
        }

        /**
         * Sets the execution level for the expiration after the cryptographic suite update date of
         * the cryptographic algorithms check of the last provided cryptographic suite
         *
         * @param level {@link Level}
         * @return this
         */
        public ValidationPolicyLoaderWithCryptoSuite andAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level level) {
            cryptographicSuite.setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(level);
            return this;
        }

    }

}
