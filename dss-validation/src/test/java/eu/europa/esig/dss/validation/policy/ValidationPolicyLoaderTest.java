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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.CryptographicConstraintWrapper;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ValidationPolicyLoaderTest {

    @Test
    void loadDefaultTest() {
        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromDefaultValidationPolicy().create();
        assertNotNull(validationPolicy);
        assertInstanceOf(EtsiValidationPolicy.class, validationPolicy);

        ValidationPolicy validationPolicyWithCryptoSuite = ValidationPolicyLoader.fromDefaultValidationPolicy()
                .withDefaultCryptographicSuite().create();
        assertNotNull(validationPolicyWithCryptoSuite);
        assertInstanceOf(ValidationPolicyWithCryptographicSuite.class, validationPolicyWithCryptoSuite);

        assertEquals(new HashSet<>(validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithms()),
                new HashSet<>(validationPolicyWithCryptoSuite.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithms()));

        assertEquals(new HashMap<>(validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithmsWithExpirationDates()),
                new HashMap<>(validationPolicyWithCryptoSuite.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithmsWithExpirationDates()));

        assertEquals(new HashSet<>(validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithms()),
                new HashSet<>(validationPolicyWithCryptoSuite.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithms()));

        assertEquals(new HashSet<>(validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsWithMinKeySizes()),
                new HashSet<>(validationPolicyWithCryptoSuite.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsWithMinKeySizes()));

        assertEquals(new HashMap<>(validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsWithExpirationDates()),
                new HashMap<>(validationPolicyWithCryptoSuite.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsWithExpirationDates()));
    }

    @Test
    void overrideDefaultPolicyTest() {
        ValidationPolicy policy = ValidationPolicyLoader.fromDefaultValidationPolicy()
                .withDefaultCryptographicSuite().create();

        Set<DigestAlgorithm> fullSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.MD5, DigestAlgorithm.SHA1,
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512,
                DigestAlgorithm.RIPEMD160, DigestAlgorithm.WHIRLPOOL));

        assertEquals(fullSet, new HashSet<>(new HashSet<>(policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithms())));

        // default crypto suite
        CryptographicConstraint altCrypto = new CryptographicConstraint();
        altCrypto.setLevel(Level.FAIL);
        ListAlgo listAlgo = new ListAlgo();
        Algo algo = new Algo();
        algo.setValue("SHA256");
        listAlgo.getAlgos().add(algo);
        altCrypto.setAcceptableDigestAlgo(listAlgo);

        CryptographicSuite altCryptoSuite = new CryptographicConstraintWrapper(altCrypto);
        
        policy = ValidationPolicyLoader.fromDefaultValidationPolicy().withCryptographicSuite(altCryptoSuite).create();

        Set<DigestAlgorithm> sha256List = Collections.singleton(DigestAlgorithm.SHA256);
        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(sha256List, new HashSet<>(policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms()));
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(sha256List, new HashSet<>(policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms()));
                }
            }
        }
        assertEquals(sha256List, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));

        for (Context context : Context.values()) {
            policy = ValidationPolicyLoader.fromDefaultValidationPolicy().withCryptographicSuiteForContext(altCryptoSuite, context).create();

            for (Context currentContext : Context.values()) {
                if (Context.EVIDENCE_RECORD == currentContext) {
                    if (context == currentContext) {
                        assertEquals(sha256List, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));
                    } else {
                        assertEquals(fullSet, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));
                    }

                } else {
                    if (context == currentContext) {
                        assertEquals(sha256List, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                        assertEquals(sha256List, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
                        assertEquals(sha256List, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
                    } else {
                        assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
                        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
                    }
                }
            }
        }

        for (Context context : Context.values()) {
            for (SubContext subContext : SubContext.values()) {
                if (Context.EVIDENCE_RECORD != context) {
                    policy = ValidationPolicyLoader.fromDefaultValidationPolicy().withCryptographicSuiteForContext(altCryptoSuite, context, subContext).create();

                    for (Context currentContext : Context.values()) {
                        if (Context.EVIDENCE_RECORD != currentContext) {
                            for (SubContext currentSubContext : SubContext.values()) {
                                if (context == currentContext && subContext == currentSubContext) {
                                    assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                                    assertEquals(sha256List, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms()));
                                } else {
                                    assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                                    assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    void overrideWithDefaultCryptographicSuiteTest() {
        // default crypto suite
        CryptographicConstraint defaultCrypto = new CryptographicConstraint();
        defaultCrypto.setLevel(Level.FAIL);
        ListAlgo listAlgo = new ListAlgo();
        Algo algo = new Algo();
        algo.setValue("SHA1");
        listAlgo.getAlgos().add(algo);
        defaultCrypto.setAcceptableDigestAlgo(listAlgo);

        ConstraintsParameters constraintsParameters = new ConstraintsParameters();
        ValidationPolicy validationPolicy = new EtsiValidationPolicy(constraintsParameters);
        constraintsParameters.setCryptographic(defaultCrypto);
        
        ValidationPolicy policy = ValidationPolicyLoader.fromValidationPolicy(validationPolicy).create();

        Set<DigestAlgorithm> sha1Set = Collections.singleton(DigestAlgorithm.SHA1);
        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(sha1Set, new HashSet<>(policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms()));
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(sha1Set, new HashSet<>(policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms()));
                }
            }
        }
        
        policy = ValidationPolicyLoader.fromValidationPolicy(validationPolicy)
                .withDefaultCryptographicSuite().create();
            
        Set<DigestAlgorithm> fullSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.MD5, DigestAlgorithm.SHA1,
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512,
                DigestAlgorithm.RIPEMD160, DigestAlgorithm.WHIRLPOOL));

        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms()));
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms()));
                }
            }
        }

        for (Context context : Context.values()) {
            policy = ValidationPolicyLoader.fromValidationPolicy(validationPolicy).withDefaultCryptographicSuiteForContext(context).create();

            for (Context currentContext : Context.values()) {
                if (Context.EVIDENCE_RECORD == currentContext) {
                    if (context == currentContext) {
                        assertEquals(fullSet, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));
                    } else {
                        assertEquals(sha1Set, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));
                    }

                } else {
                    if (context == currentContext) {
                        assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
                        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
                    } else {
                        assertEquals(sha1Set, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                        assertEquals(sha1Set, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
                        assertEquals(sha1Set, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
                    }
                }
            }
        }

        for (Context context : Context.values()) {
            for (SubContext subContext : SubContext.values()) {
                if (Context.EVIDENCE_RECORD != context) {
                    policy = ValidationPolicyLoader.fromValidationPolicy(validationPolicy).withDefaultCryptographicSuiteForContext(context, subContext).create();

                    for (Context currentContext : Context.values()) {
                        if (Context.EVIDENCE_RECORD != currentContext) {
                            for (SubContext currentSubContext : SubContext.values()) {
                                if (context == currentContext && subContext == currentSubContext) {
                                    assertEquals(sha1Set, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                                    assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms()));
                                } else {
                                    assertEquals(sha1Set, new HashSet<>(policy.getSignatureCryptographicConstraint(currentContext).getAcceptableDigestAlgorithms()));
                                    assertEquals(sha1Set, new HashSet<>(policy.getCertificateCryptographicConstraint(currentContext, currentSubContext).getAcceptableDigestAlgorithms()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    void loadFromFilesTest() {
        ValidationPolicy policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/no-crypto-constraint-policy.xml")).create();
        assertNotNull(policy);
        assertInstanceOf(EtsiValidationPolicy.class, policy);

        Set<DigestAlgorithm> emptySet = Collections.emptySet();
        for (Context context : Context.values()) {
            if (Context.EVIDENCE_RECORD != context) {
                assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(context).getAcceptableDigestAlgorithms()));
                for (SubContext subContext : SubContext.values()) {
                    assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(context, subContext).getAcceptableDigestAlgorithms()));
                }
            }
        }

        policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/no-crypto-constraint-policy.xml"))
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.json"), Context.SIGNATURE)
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml"), Context.TIMESTAMP, SubContext.SIGNING_CERT)
                .create();

        Set<DigestAlgorithm> fullSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.MD5, DigestAlgorithm.SHA1,
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512,
                DigestAlgorithm.RIPEMD160, DigestAlgorithm.WHIRLPOOL));

        assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.COUNTER_SIGNATURE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));

        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.COUNTER_SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.COUNTER_SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.CERTIFICATE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));

        CryptographicConstraint altCrypto = new CryptographicConstraint();
        altCrypto.setLevel(Level.FAIL);
        ListAlgo listAlgo = new ListAlgo();
        Algo algo = new Algo();
        algo.setValue("SHA256");
        listAlgo.getAlgos().add(algo);
        altCrypto.setAcceptableDigestAlgo(listAlgo);
        CryptographicSuite altCryptoSuite = new CryptographicConstraintWrapper(altCrypto);

        // overwrite
        policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/no-crypto-constraint-policy.xml"))
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.json"), Context.SIGNATURE)
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml"), Context.TIMESTAMP, SubContext.SIGNING_CERT)
                .withCryptographicSuiteForContext(altCryptoSuite, Context.SIGNATURE, SubContext.SIGNING_CERT)
                .create();

        Set<DigestAlgorithm> sha256Set = Collections.singleton(DigestAlgorithm.SHA256);

        assertEquals(fullSet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.COUNTER_SIGNATURE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getSignatureCryptographicConstraint(Context.CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getEvidenceRecordCryptographicConstraint().getAcceptableDigestAlgorithms()));

        assertEquals(sha256Set, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(fullSet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.COUNTER_SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.COUNTER_SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.CERTIFICATE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithms()));
        assertEquals(emptySet, new HashSet<>(policy.getCertificateCryptographicConstraint(Context.CERTIFICATE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithms()));
    }

    @Test
    void loadWithLevelsTest() {
        ValidationPolicy policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/all-fail-policy.xml"))
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.json"), Context.SIGNATURE)
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml"), Context.TIMESTAMP, SubContext.SIGNING_CERT)
                .create();

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/all-fail-policy.xml"))
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.json"), Context.SIGNATURE)
                .andLevel(Level.WARN)
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml"), Context.TIMESTAMP, SubContext.SIGNING_CERT)
                .andLevel(Level.INFORM)
                .create();

        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        policy = ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/policy/all-fail-policy.xml"))
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.json"), Context.SIGNATURE)
                .andLevel(Level.WARN)
                .andAcceptableDigestAlgorithmsLevel(Level.FAIL)
                .andAcceptableEncryptionAlgorithmsLevel(Level.FAIL)
                .withCryptographicSuiteForContext(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml"), Context.TIMESTAMP, SubContext.SIGNING_CERT)
                .andLevel(Level.INFORM)
                .andAcceptableEncryptionAlgorithmsMiniKeySizeLevel(Level.FAIL)
                .andAlgorithmsExpirationDateLevel(Level.FAIL)
                .andAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level.FAIL)
                .create();

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getSignatureCryptographicConstraint(Context.SIGNATURE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.WARN, policy.getCertificateCryptographicConstraint(Context.SIGNATURE, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.TIMESTAMP).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.INFORM, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.TIMESTAMP, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getSignatureCryptographicConstraint(Context.REVOCATION).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.SIGNING_CERT).getAlgorithmsExpirationDateAfterUpdateLevel());

        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableDigestAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAcceptableEncryptionAlgorithmsMiniKeySizeLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateLevel());
        assertEquals(Level.FAIL, policy.getCertificateCryptographicConstraint(Context.REVOCATION, SubContext.CA_CERTIFICATE).getAlgorithmsExpirationDateAfterUpdateLevel());
    }

    @Test
    void notSupportedPolicyFileTest() {
        Exception exception = assertThrows(UnsupportedOperationException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy(new File("src/test/resources/diag-data/crypto-suite/dss-crypto-suite.xml")));
        assertEquals("The validation policy is not valid or no suitable ValidationPolicyFactory has been found! " +
                "Please ensure the provided policy file is valid and 'dss-policy-jaxb' module is added to the classpath " +
                "or create your own implementation for a custom policy.", exception.getMessage());
    }

    @Test
    void notSupportedCryptoSuiteFileTest() {
        Exception exception = assertThrows(UnsupportedOperationException.class, () ->
                ValidationPolicyLoader.fromDefaultValidationPolicy().withCryptographicSuite(new File("src/test/resources/diag-data/policy/no-crypto-constraint-policy.xml")));
        assertEquals("The cryptographic suite file is not valid or no suitable CryptographicSuiteFactory has been found! " +
                "Please ensure the provided policy file is valid and 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' module is added to the classpath or " +
                "create your own implementation for a custom cryptographic suite policy.", exception.getMessage());
    }

    @Test
    void policyNullTest() {
        Exception exception = assertThrows(NullPointerException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy((DSSDocument) null));
        assertEquals("Validation policy document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy((InputStream) null));
        assertEquals("Validation policy stream cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy((File) null));
        assertEquals("Validation policy file cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy((String) null));
        assertEquals("Validation policy file path cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                ValidationPolicyLoader.fromValidationPolicy((ValidationPolicy) null));
        assertEquals("Validation policy cannot be null!", exception.getMessage());
    }

    @Test
    void cryptoSuiteNullTest() {
        ValidationPolicyLoader validationPolicyLoader = ValidationPolicyLoader.fromDefaultValidationPolicy();
        Exception exception = assertThrows(NullPointerException.class, () ->
                validationPolicyLoader.withCryptographicSuite((DSSDocument) null));
        assertEquals("Cryptographic suite document cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                validationPolicyLoader.withCryptographicSuite((InputStream) null));
        assertEquals("Cryptographic suite stream cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                validationPolicyLoader.withCryptographicSuite((File) null));
        assertEquals("Cryptographic suite file cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                validationPolicyLoader.withCryptographicSuite((String) null));
        assertEquals("Cryptographic suite file path cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                validationPolicyLoader.withCryptographicSuite((CryptographicSuite) null));
        assertEquals("Cryptographic suite cannot be null!", exception.getMessage());
    }

}
