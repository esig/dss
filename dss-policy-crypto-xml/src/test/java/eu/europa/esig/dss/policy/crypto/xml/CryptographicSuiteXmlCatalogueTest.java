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
package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.enumerations.CryptographicSuiteRecommendation;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteAlgorithm;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteEvaluation;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteMetadata;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteParameter;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmIdentifierType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.EvaluationType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.InformationType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ParameterType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.PolicyNameType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.PublisherType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ValidityType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.algocat.ExtensionType;
import jakarta.xml.bind.JAXBElement;
import org.junit.jupiter.api.Test;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicSuiteXmlCatalogueTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd";
    private static final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ssXXX";

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";
    private static final String QLENGTH = "glength";

    @Test
    void getAcceptableDigestAlgorithmsTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.buildAlgorithmList()));

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224, 
                Collections.singletonList(new EvaluationDTO("2029-01-01+00:00"))));
        
        cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        List<CryptographicSuiteAlgorithm> expectedList = new ArrayList<>();

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA256, null));
        
        cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA384, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA512, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA3_256, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA3_384, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA3_512, null));
        cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));
        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));
        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));
        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));
        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void buildAlgorithmListWithEmptyListTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();
        // No algorithms added

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        assertTrue(cryptographicSuite.buildAlgorithmList().isEmpty());
    }

    @Test
    void buildAlgorithmListWithDuplicateAlgorithmsTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2021-01-01+00:00"))));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        
        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // duplicate entries test

        policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2021-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01+00:00"))));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // opposite test

        policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2021-01-01+00:00"))));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        
        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // null test

        policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2021-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO(null))));

        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // opposite null test

        policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO(null))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2021-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01+00:00"))));

        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void buildAlgorithmListWithUnknownAlgorithmTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        // Assuming this creates an unknown algorithm
        AlgorithmType unknownAlgo = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("SHA999");
        algorithmIdentifierType.getObjectIdentifier().add("1.2.3.1.50");
        unknownAlgo.setAlgorithmIdentifier(algorithmIdentifierType);
        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2030-12-31+00:00"));
        eval.setValidity(validityType);
        unknownAlgo.getEvaluation().add(eval);

        policy.getAlgorithm().add(unknownAlgo);
        
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName("SHA999");
        algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList("1.2.3.1.50"));
        algorithm.setAlgorithmIdentifierURIs(Collections.emptyList());
        algorithm.setEvaluationList(createEvaluations(Collections.singletonList(
                new EvaluationDTO("2030-12-31", null)
        )));
        algorithm.setInformationTextList(Collections.emptyList());

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        // return all extracted values
        assertEquals(Collections.singletonList(algorithm), cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsEmptyList() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        assertTrue(cryptographicSuite.buildAlgorithmList().isEmpty(), "Expected no signature algorithms for empty list.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsUnknownAlgorithmIgnored() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        // Assuming this creates an unknown algorithm
        AlgorithmType unknownAlgo = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("UNKNOWN_ALGO");
        algorithmIdentifierType.getObjectIdentifier().add("1.2.3.1.50");
        unknownAlgo.setAlgorithmIdentifier(algorithmIdentifierType);
        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2030-12-31+00:00"));
        eval.setValidity(validityType);
        unknownAlgo.getEvaluation().add(eval);

        policy.getAlgorithm().add(unknownAlgo);

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName("UNKNOWN_ALGO");
        algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList("1.2.3.1.50"));
        algorithm.setAlgorithmIdentifierURIs(Collections.emptyList());
        algorithm.setEvaluationList(createEvaluations(Collections.singletonList(new EvaluationDTO("2030-12-31"))));
        algorithm.setInformationTextList(Collections.emptyList());

        // return all extracted values
        assertEquals(Collections.singletonList(algorithm), cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithStartDatesTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2000-01-01+00:00", "2029-01-01+00:00", null))));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        List<CryptographicSuiteAlgorithm> expectedList = new ArrayList<>();

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2000-01-01", "2029-01-01", null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO("2000-01-01+00:00",  null, null))));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2000-01-01", null, null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                ))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();
        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                )))
        ));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2029-01-01", Collections.emptyList())
                )
        ));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));
        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // Add DigestAlgorithm definition
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.emptyList())
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesDuplicatesHandledCorrectly() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(1024, PLENGTH)))
        )));
        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(2048, PLENGTH)))
        )));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH)))
        )));

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(2048, PLENGTH)))
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // Add DigestAlgorithm definition
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA512,Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesMissingParameter() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmType dsa = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("DSA");
        algorithmIdentifierType.getObjectIdentifier().add("1.2.840.10040.4.1");

        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2029-01-01+00:00"));
        ParameterType parameterType = new ParameterType();
        parameterType.setName(PLENGTH);
        eval.setValidity(validityType);
        eval.getParameter().add(parameterType);

        dsa.getEvaluation().add(eval);
        dsa.setAlgorithmIdentifier(algorithmIdentifierType);

        policy.getAlgorithm().add(dsa);
        
        // Add DigestAlgorithm definition
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(null, PLENGTH)))
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH))),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList((
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        ))));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+00:00", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                ))
        )));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2029-01-01", Collections.emptyList())
                )
        ));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));
        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // Add DigestAlgorithm definition
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01+00:00", Collections.emptyList())
        )));

        cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithStartDatesTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2020-01-01+00:00", "2029-01-01+00:00", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                ))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmXmlDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                new EvaluationDTO("2000-01-01+00:00", "2029-01-01+00:00", Collections.emptyList())
        )));

        // Add DigestAlgorithm definition
        policy.getAlgorithm().add(createDigestAlgorithmXmlDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2010-01-01+00:00", "2029-01-01+00:00", Collections.emptyList())
        )));

        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(policy);

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();
        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2020-01-01", "2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                )))
        ));
        expected.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2000-01-01", "2029-01-01", Collections.emptyList())
                )
        ));

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2010-01-01", "2029-01-01", Collections.emptyList())
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getCryptographicSuiteUpdateDateTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();
        CryptographicSuiteXmlCatalogue cryptographicSuite = new CryptographicSuiteXmlCatalogue(securitySuitabilityPolicyType);

        CryptographicSuiteMetadata metadata = cryptographicSuite.buildMetadata();
        assertNotNull(metadata);
        assertNull(metadata.getPolicyIssueDate());

        securitySuitabilityPolicyType.setPolicyIssueDate(toGregorianCalendar("2024-10-13T00:00:00+01:00"));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        metadata = cryptographicSuite.buildMetadata();
        assertNotNull(metadata);
        assertEquals(calendar.getTime(), metadata.getPolicyIssueDate());
    }

    @Test
    void testBuildMetadataComplete() {
        PolicyNameType policyName = new PolicyNameType();
        policyName.setName("Test Policy");
        policyName.setObjectIdentifier("1.2.3.4.5");
        policyName.setURI("http://policy.example.com");

        PublisherType publisher = new PublisherType();
        publisher.setName("Example Publisher");
        publisher.setAddress("123 Example Street");
        publisher.setURI("http://publisher.example.com");

        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();
        policy.setPolicyName(policyName);
        policy.setPublisher(publisher);
        policy.setPolicyIssueDate(toGregorianCalendar("2025-01-01T10:00:00+00:00"));
        policy.setNextUpdate(toGregorianCalendar("2025-06-01T10:00:00+00:00"));
        policy.setUsage("general");
        policy.setVersion("2");
        policy.setLang("fr");
        policy.setId("policy-123");

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);

        CryptographicSuiteMetadata metadata = catalogue.buildMetadata();

        assertEquals("Test Policy", metadata.getPolicyName());
        assertEquals("1.2.3.4.5", metadata.getPolicyOID());
        assertEquals("http://policy.example.com", metadata.getPolicyURI());
        assertEquals("Example Publisher", metadata.getPublisherName());
        assertEquals("123 Example Street", metadata.getPublisherAddress());
        assertEquals("http://publisher.example.com", metadata.getPublisherURI());
        assertEquals(toDateTime("2025-01-01T10:00:00+00:00"), metadata.getPolicyIssueDate());
        assertEquals(toDateTime("2025-06-01T10:00:00+00:00"), metadata.getNextUpdate());
        assertEquals("general", metadata.getUsage());
        assertEquals("2", metadata.getVersion());
        assertEquals("fr", metadata.getLang());
        assertEquals("policy-123", metadata.getId());
    }

    @Test
    void testBuildMetadataWithMissingOptionalFields() {
        PolicyNameType policyName = new PolicyNameType();
        policyName.setName("Minimal Policy");

        PublisherType publisher = new PublisherType();
        publisher.setName("Minimal Publisher");

        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();
        policy.setPolicyName(policyName);
        policy.setPublisher(publisher);
        policy.setPolicyIssueDate(toGregorianCalendar("2025-01-01T10:00:00+00:00"));

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);

        CryptographicSuiteMetadata metadata = catalogue.buildMetadata();

        assertEquals("Minimal Policy", metadata.getPolicyName());
        assertNull(metadata.getPolicyOID());
        assertNull(metadata.getPolicyURI());
        assertEquals("Minimal Publisher", metadata.getPublisherName());
        assertNull(metadata.getPublisherAddress());
        assertNull(metadata.getPublisherURI());
        assertEquals(toDateTime("2025-01-01T10:00:00+00:00"), metadata.getPolicyIssueDate());
        assertNull(metadata.getNextUpdate());
        assertNull(metadata.getUsage());
        assertEquals("1", metadata.getVersion()); // default
        assertEquals("en", metadata.getLang());   // default
        assertNull(metadata.getId());
    }

    @Test
    void testSingleAlgorithmWithFullDetails() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        // AlgorithmIdentifier
        AlgorithmIdentifierType identifier = new AlgorithmIdentifierType();
        identifier.setName("SHA256withRSA");
        identifier.getObjectIdentifier().add("1.2.840.113549.1.1.11");
        identifier.getURI().add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

        // Parameter
        ParameterType param = new ParameterType();
        param.setName("moduluslength");
        param.setMin(2048);
        param.setMax(4096);

        // Validity
        ValidityType validity = new ValidityType();
        validity.setStart(toGregorianCalendar("2020-01-01+00:00"));
        validity.setEnd(toGregorianCalendar("2030-01-01+00:00"));

        // Evaluation
        EvaluationType eval = new EvaluationType();
        eval.getParameter().add(param);
        eval.setValidity(validity);

        // MoreDetails extension (AlgorithmUsage + Recommendation)
        ExtensionType extensionType = new ExtensionType();
        JAXBElement<String> algorithmUsage = new JAXBElement<>(new QName("AlgorithmUsage"), String.class, "http://uri.etsi.org/19322/sign_data");
        extensionType.getContent().add(algorithmUsage);
        JAXBElement<String> recommendation = new JAXBElement<>(new QName("Recommendation"), String.class, "R");
        extensionType.getContent().add(recommendation);

        JAXBElement<ExtensionType> moreDetails = new JAXBElement<>(new QName("MoreDetails"), ExtensionType.class, extensionType);
        eval.setAny(moreDetails);

        // Information
        InformationType info = new InformationType();
        info.getText().add("Widely used secure algorithm");

        AlgorithmType alg = new AlgorithmType();
        alg.setAlgorithmIdentifier(identifier);
        alg.getEvaluation().add(eval);
        alg.setInformation(info);

        policy.getAlgorithm().add(alg);

        // Execute
        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteAlgorithm rsa = result.get(0);
        assertEquals("SHA256withRSA", rsa.getAlgorithmIdentifierName());
        assertEquals(Collections.singletonList("1.2.840.113549.1.1.11"), rsa.getAlgorithmIdentifierOIDs());
        assertEquals(Collections.singletonList("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), rsa.getAlgorithmIdentifierURIs());
        assertEquals(Collections.singletonList("Widely used secure algorithm"), rsa.getInformationTextList());
        assertEquals(1, rsa.getEvaluationList().size());

        CryptographicSuiteEvaluation evaluation = rsa.getEvaluationList().get(0);
        assertEquals(evaluation.getParameterList().size(), 1);

        CryptographicSuiteParameter parameter = evaluation.getParameterList().get(0);
        assertEquals("moduluslength", parameter.getName());
        assertEquals(2048, parameter.getMin());
        assertEquals(4096, parameter.getMax());

        assertEquals(toDate("2020-01-01"), evaluation.getValidityStart());
        assertEquals(toDate("2030-01-01"), evaluation.getValidityEnd());
        assertEquals(Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_DATA), evaluation.getAlgorithmUsage());
        assertEquals(CryptographicSuiteRecommendation.RECOMMENDED, evaluation.getRecommendation());
    }

    @Test
    void testAlgorithmWithoutOptionalFields() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmIdentifierType identifier = new AlgorithmIdentifierType();
        identifier.setName("SHA256");
        identifier.getObjectIdentifier().add("2.16.840.1.101.3.4.2.1");

        AlgorithmType alg = new AlgorithmType();
        alg.setAlgorithmIdentifier(identifier);

        policy.getAlgorithm().add(alg);

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteAlgorithm sha256 = result.get(0);
        assertEquals("SHA256", sha256.getAlgorithmIdentifierName());
        assertEquals(Collections.singletonList("2.16.840.1.101.3.4.2.1"), sha256.getAlgorithmIdentifierOIDs());
        assertTrue(sha256.getAlgorithmIdentifierURIs().isEmpty());
        assertTrue(sha256.getInformationTextList().isEmpty());
        assertTrue(sha256.getEvaluationList().isEmpty());
    }

    @Test
    void testMultipleAlgorithms() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmIdentifierType id1 = new AlgorithmIdentifierType();
        id1.setName("RSA");
        id1.getObjectIdentifier().add("1.2.840.113549.1.1.1");

        AlgorithmIdentifierType id2 = new AlgorithmIdentifierType();
        id2.setName("ECDSA");
        id2.getObjectIdentifier().add("1.2.840.10045.2.1");

        AlgorithmType alg1 = new AlgorithmType();
        alg1.setAlgorithmIdentifier(id1);
        AlgorithmType alg2 = new AlgorithmType();
        alg2.setAlgorithmIdentifier(id2);

        policy.getAlgorithm().addAll(Arrays.asList(alg1, alg2));

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(2, result.size());
        assertEquals(Arrays.asList("RSA", "ECDSA"), result.stream().map(CryptographicSuiteAlgorithm::getAlgorithmIdentifierName).collect(Collectors.toList()));
    }

    @Test
    void testUnknownAlgorithmUsageUriResultsInNull() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmIdentifierType identifier = new AlgorithmIdentifierType();
        identifier.setName("TestAlg");
        identifier.getObjectIdentifier().add("1.2.3");

        // MoreDetails extension (AlgorithmUsage + Recommendation)
        ExtensionType extensionType = new ExtensionType();
        JAXBElement<String> algorithmUsage = new JAXBElement<>(new QName("AlgorithmUsage"), String.class, "http://uri.etsi.org/19322/unknown_usage");
        extensionType.getContent().add(algorithmUsage);
        JAXBElement<String> recommendation = new JAXBElement<>(new QName("Recommendation"), String.class, "X");  // invalid value
        extensionType.getContent().add(recommendation);

        // Evaluation
        EvaluationType eval = new EvaluationType();

        JAXBElement<ExtensionType> moreDetails = new JAXBElement<>(new QName("MoreDetails"), ExtensionType.class, extensionType);
        eval.setAny(moreDetails);

        AlgorithmType alg = new AlgorithmType();
        alg.setAlgorithmIdentifier(identifier);
        alg.getEvaluation().add(eval);

        policy.getAlgorithm().add(alg);

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteEvaluation evaluation = result.get(0).getEvaluationList().get(0);
        assertTrue(evaluation.getAlgorithmUsage().isEmpty());
        assertNull(evaluation.getRecommendation());
    }

    @Test
    void testEvaluationWithoutValidityDates() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmIdentifierType identifier = new AlgorithmIdentifierType();
        identifier.setName("TestAlg");
        identifier.getObjectIdentifier().add("1.2.3");

        EvaluationType eval = new EvaluationType();
        ValidityType validity = new ValidityType(); // no start, no end
        eval.setValidity(validity);

        AlgorithmType alg = new AlgorithmType();
        alg.setAlgorithmIdentifier(identifier);
        alg.getEvaluation().add(eval);

        policy.getAlgorithm().add(alg);

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteEvaluation evaluation = result.get(0).getEvaluationList().get(0);
        assertNull(evaluation.getValidityStart());
        assertNull(evaluation.getValidityEnd());
    }

    @Test
    void testParameterWithOnlyMinOrMax() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmIdentifierType identifier = new AlgorithmIdentifierType();
        identifier.setName("TestAlg");
        identifier.getObjectIdentifier().add("1.2.3");

        ParameterType param1 = new ParameterType();
        param1.setName("p1");
        param1.setMin(1024);

        ParameterType param2 = new ParameterType();
        param2.setName("p2");
        param2.setMax(8192);

        EvaluationType eval = new EvaluationType();
        eval.getParameter().addAll(Arrays.asList(param1, param2));
        ValidityType validity = new ValidityType();
        eval.setValidity(validity);

        AlgorithmType alg = new AlgorithmType();
        alg.setAlgorithmIdentifier(identifier);
        alg.getEvaluation().add(eval);

        policy.getAlgorithm().add(alg);

        CryptographicSuiteXmlCatalogue catalogue = new CryptographicSuiteXmlCatalogue(policy);
        List<CryptographicSuiteAlgorithm> result = catalogue.buildAlgorithmList();

        assertEquals(1, result.size());
        List<CryptographicSuiteParameter> params = result.get(0).getEvaluationList().get(0).getParameterList();
        assertEquals(2, params.size());
        assertEquals(1024, params.get(0).getMin());
        assertNull(params.get(0).getMax());
        assertNull(params.get(1).getMin());
        assertEquals(8192, params.get(1).getMax());
    }

    private AlgorithmType createDigestAlgorithmXmlDefinition(DigestAlgorithm digestAlgorithm, List<EvaluationDTO> evaluationList) {
        AlgorithmType algorithmType = new AlgorithmType();

        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName(digestAlgorithm.getName());
        if (digestAlgorithm.getOid() != null) {
            algorithmIdentifierType.getObjectIdentifier().add(digestAlgorithm.getOid());
        }
        if (digestAlgorithm.getUri() != null) {
            algorithmIdentifierType.getURI().add(digestAlgorithm.getUri());
        }

        algorithmType.setAlgorithmIdentifier(algorithmIdentifierType);
        algorithmType.getEvaluation().addAll(createEvaluationTypes(evaluationList));

        return algorithmType;
    }

    private AlgorithmType createEncryptionAlgorithmXmlDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationDTO> evaluationList) {
        AlgorithmType algorithmType = new AlgorithmType();

        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName(encryptionAlgorithm.getName());
        if (encryptionAlgorithm.getOid() != null) {
            algorithmIdentifierType.getObjectIdentifier().add(encryptionAlgorithm.getOid());
        }

        algorithmType.setAlgorithmIdentifier(algorithmIdentifierType);
        algorithmType.getEvaluation().addAll(createEvaluationTypes(evaluationList));

        return algorithmType;
    }

    private AlgorithmType createSignatureAlgorithmXmlDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationDTO> evaluationList) {
        AlgorithmType algorithmType = new AlgorithmType();

        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName(signatureAlgorithm.getName());
        if (signatureAlgorithm.getOid() != null) {
            algorithmIdentifierType.getObjectIdentifier().add(signatureAlgorithm.getOid());
        }
        if (signatureAlgorithm.getUri() != null) {
            algorithmIdentifierType.getURI().add(signatureAlgorithm.getUri());
        }

        algorithmType.setAlgorithmIdentifier(algorithmIdentifierType);
        algorithmType.getEvaluation().addAll(createEvaluationTypes(evaluationList));

        return algorithmType;
    }
    
    private List<EvaluationType> createEvaluationTypes(List<EvaluationDTO> evaluationList) {
        List<EvaluationType> result = new ArrayList<>();
        if (evaluationList != null && !evaluationList.isEmpty()) {
            for (EvaluationDTO evaluationDTO : evaluationList) {
                EvaluationType evaluationType = new EvaluationType();

                ValidityType validityType = new ValidityType();
                if (evaluationDTO.validityStart != null) {
                    validityType.setStart(toGregorianCalendar(evaluationDTO.validityStart));
                }
                if (evaluationDTO.validityEnd != null) {
                    validityType.setEnd(toGregorianCalendar(evaluationDTO.validityEnd));
                }
                evaluationType.setValidity(validityType);

                if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
                    for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                        ParameterType parameterType = new ParameterType();
                        parameterType.setMin(parameterDTO.minKeyLength);
                        parameterType.setName(parameterDTO.parameterName);
                        evaluationType.getParameter().add(parameterType);
                    }
                }
                result.add(evaluationType);
            }
            
        } else {
            EvaluationType evaluationType = new EvaluationType();

            ValidityType validityType = new ValidityType();
            evaluationType.setValidity(validityType);

            result.add(evaluationType);
        }
        return result;
    }

    private XMLGregorianCalendar toGregorianCalendar(String dateStr) {
        try {
            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
            return datatypeFactory.newXMLGregorianCalendar(dateStr);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private CryptographicSuiteAlgorithm createDigestAlgorithmDefinition(DigestAlgorithm digestAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(digestAlgorithm.getName());
        if (digestAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(digestAlgorithm.getOid()));
        }
        if (digestAlgorithm.getUri() != null) {
            algorithm.setAlgorithmIdentifierURIs(Collections.singletonList(digestAlgorithm.getUri()));
        }

        algorithm.setEvaluationList(createEvaluations(evaluationList));
        algorithm.setInformationTextList(Collections.emptyList());

        return algorithm;
    }

    private CryptographicSuiteAlgorithm createEncryptionAlgorithmDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(encryptionAlgorithm.getName());
        if (encryptionAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(encryptionAlgorithm.getOid()));
        }
        algorithm.setAlgorithmIdentifierURIs(Collections.emptyList());

        algorithm.setEvaluationList(createEvaluations(evaluationList));
        algorithm.setInformationTextList(Collections.emptyList());

        return algorithm;
    }

    private CryptographicSuiteAlgorithm createSignatureAlgorithmDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(signatureAlgorithm.getName());
        if (signatureAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(signatureAlgorithm.getOid()));
        }
        if (signatureAlgorithm.getUri() != null) {
            algorithm.setAlgorithmIdentifierURIs(Collections.singletonList(signatureAlgorithm.getUri()));
        }

        algorithm.setEvaluationList(createEvaluations(evaluationList));
        algorithm.setInformationTextList(Collections.emptyList());

        return algorithm;
    }

    private List<CryptographicSuiteEvaluation> createEvaluations(List<EvaluationDTO> evaluationList) {
        List<CryptographicSuiteEvaluation> result = new ArrayList<>();
        if (evaluationList != null && !evaluationList.isEmpty()) {
            for (EvaluationDTO evaluationDTO : evaluationList) {
                CryptographicSuiteEvaluation evaluation = new CryptographicSuiteEvaluation();
                evaluation.setValidityStart(toDate(evaluationDTO.validityStart));
                evaluation.setValidityEnd(toDate(evaluationDTO.validityEnd));

                List<CryptographicSuiteParameter> parameters = new ArrayList<>();
                if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
                    for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                        CryptographicSuiteParameter parameter = new CryptographicSuiteParameter();
                        parameter.setMin(parameterDTO.minKeyLength);
                        parameter.setName(parameterDTO.parameterName);
                        parameters.add(parameter);
                    }
                }
                evaluation.setParameterList(parameters);
                evaluation.setAlgorithmUsage(Collections.emptyList()); // not supported
                result.add(evaluation);
            }

        } else {
            CryptographicSuiteEvaluation evaluationType = new CryptographicSuiteEvaluation();
            evaluationType.setParameterList(Collections.emptyList());
            evaluationType.setAlgorithmUsage(Collections.emptyList());
            result.add(evaluationType);
        }
        return result;
    }

    private Date toDate(final String str) {
        if (str == null) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
            sdf.setTimeZone(TimeZone.getTimeZone("GMT+0"));
            return sdf.parse(str);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private Date toDateTime(final String str) {
        if (str == null) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT);
            return sdf.parse(str);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private static class EvaluationDTO {

        private final String validityStart;
        private final String validityEnd;
        private final List<ParameterDTO> parameterList;

        public EvaluationDTO(final String validityEnd) {
            this(null, validityEnd, null);
        }

        public EvaluationDTO(final String validityEnd, final List<ParameterDTO> parameterList) {
            this(null, validityEnd, parameterList);
        }

        public EvaluationDTO(final String validityStart, final String validityEnd, final List<ParameterDTO> parameterList) {
            this.validityStart = validityStart;
            this.validityEnd = validityEnd;
            this.parameterList = parameterList;
        }

    }

    private static class ParameterDTO {
        private final Integer minKeyLength;
        private final String parameterName;

        public ParameterDTO(final Integer minKeyLength, final String parameterName) {
            this.minKeyLength = minKeyLength;
            this.parameterName = parameterName;
        }
    }

}
