package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmIdentifierType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.AlgorithmType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.EvaluationType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ParameterType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ValidityType;
import org.junit.jupiter.api.Test;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicSuiteXmlWrapperTest {

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";
    private static final String QLENGTH = "glength";

    @Test
    void getAcceptableDigestAlgorithmsTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, 
                Arrays.asList(new EvaluationDTO("2029-01-01"))));

        Set<DigestAlgorithm> expectedSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224));
        cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));
        
        expectedSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256));
        cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        securitySuitabilityPolicyType.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));
        cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);

        expectedSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));
    }

    @Test
    void getAcceptableDigestAlgorithmsWithEmptyListTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();
        // No algorithms added

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        Map<DigestAlgorithm, Date> result = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        assertTrue(result.isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithDuplicateAlgorithmsTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Arrays.asList(new EvaluationDTO("2030-01-01"))));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null)); // Duplicate

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        Map<DigestAlgorithm, Date> result = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        assertEquals(Collections.singletonMap(DigestAlgorithm.SHA256, null), result);
    }

    @Test
    void getAcceptableDigestAlgorithmsWithUnknownAlgorithmTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        // Assuming this creates an unknown algorithm
        AlgorithmType unknownAlgo = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("SHA999");
        algorithmIdentifierType.getObjectIdentifier().add("1.2.3.1.50");
        unknownAlgo.setAlgorithmIdentifier(algorithmIdentifierType);
        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2030-12-31+01:00"));
        eval.setValidity(validityType);
        unknownAlgo.getEvaluation().add(eval);

        policy.getAlgorithm().add(unknownAlgo);

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        assertTrue(cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates().isEmpty());
    }
    @Test
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Arrays.asList(new EvaluationDTO("2029-01-01+00:00"))));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        policy.getAlgorithm().add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        Map<DigestAlgorithm, Date> result = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();
        calendar.set(2029, Calendar.JANUARY, 1);

        Map<DigestAlgorithm, Date> expected = new HashMap<>();
        expected.put(DigestAlgorithm.SHA224, calendar.getTime());
        expected.put(DigestAlgorithm.SHA256, null);
        expected.put(DigestAlgorithm.SHA384, null);
        expected.put(DigestAlgorithm.SHA512, null);
        expected.put(DigestAlgorithm.SHA3_256, null);
        expected.put(DigestAlgorithm.SHA3_384, null);
        expected.put(DigestAlgorithm.SHA3_512, null);

        assertEquals(expected, new HashMap<>(result));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsEmptyList() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        List<EncryptionAlgorithm> algorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();

        assertTrue(algorithms.isEmpty(), "Expected no encryption algorithms for empty list.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsUnknownAlgorithmIgnored() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        // Assuming this creates an unknown algorithm
        AlgorithmType unknownAlgo = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("UNKNOWN_ALGO");
        algorithmIdentifierType.getObjectIdentifier().add("1.2.3.1.50");
        unknownAlgo.setAlgorithmIdentifier(algorithmIdentifierType);
        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2030-12-31+01:00"));
        eval.setValidity(validityType);
        unknownAlgo.getEvaluation().add(eval);

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        List<EncryptionAlgorithm> algorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();

        assertTrue(algorithms.isEmpty(), "Unknown algorithm should be ignored or not parsed.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                ))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.emptyList())
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);

        Set<EncryptionAlgorithm> expected = new HashSet<>(Arrays.asList(
                EncryptionAlgorithm.DSA, EncryptionAlgorithm.RSA, EncryptionAlgorithm.RSASSA_PSS, EncryptionAlgorithm.ECDSA));

        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableEncryptionAlgorithms()));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesDuplicatesHandledCorrectly() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(1024, PLENGTH)))
        )));
        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO(null, Arrays.asList(new ParameterDTO(2048, PLENGTH)))
        )));

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);

        Set<EncryptionAlgorithmWithMinKeySize> expected = new HashSet<>(Collections.singletonList(
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1024)));

        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes()));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesMissingParameter() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        AlgorithmType dsa = new AlgorithmType();
        AlgorithmIdentifierType algorithmIdentifierType = new AlgorithmIdentifierType();
        algorithmIdentifierType.setName("DSA");

        EvaluationType eval = new EvaluationType();
        ValidityType validityType = new ValidityType();
        validityType.setEnd(toGregorianCalendar("2029-01-01"));
        ParameterType parameterType = new ParameterType();
        parameterType.setName(PLENGTH);
        eval.setValidity(validityType);
        eval.getParameter().add(parameterType);

        dsa.getEvaluation().add(eval);
        dsa.setAlgorithmIdentifier(algorithmIdentifierType);

        policy.getAlgorithm().add(dsa);

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);
        assertTrue(cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes().isEmpty(),
                "Malformed parameter should result in exclusion.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH))),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.emptyList())
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);

        Set<EncryptionAlgorithmWithMinKeySize> expected = new HashSet<>(Arrays.asList(
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0)
        ));

        assertEquals(expected, new HashSet<>(cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes()));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithExpirationDatesTest() {
        SecuritySuitabilityPolicyType policy = new SecuritySuitabilityPolicyType();

        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01+01:00", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH))),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)))
        )));

        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01+01:00", Collections.emptyList())
        )));
        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        policy.getAlgorithm().add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01+01:00", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+01:00", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));
        policy.getAlgorithm().add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01+01:00", Arrays.asList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01+01:00", Arrays.asList(new ParameterDTO(3000, MODULES_LENGTH)))
        )));

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(policy);

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT+1"));
        cal.clear();
        Map<EncryptionAlgorithmWithMinKeySize, Date> expected = new HashMap<>();

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1900), cal.getTime());
        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 3000), null);

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900), cal.getTime());

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 3000), cal.getTime());

        cal.set(2029, Calendar.JANUARY, 1);
        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1900), cal.getTime());

        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 3000), cal.getTime());

        expected.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0), null);

        assertEquals(expected, new HashMap<>(cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates()));
    }

    @Test
    void getCryptographicSuiteUpdateDateTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();
        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());

        securitySuitabilityPolicyType.setPolicyIssueDate(toGregorianCalendar("2024-10-13T00:00:00.000+01:00"));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

    private AlgorithmType createDigestAlgorithmDefinition(DigestAlgorithm digestAlgorithm, List<EvaluationDTO> evaluationList) {
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

    private AlgorithmType createEncryptionAlgorithmDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationDTO> evaluationList) {
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

    private AlgorithmType createSignatureAlgorithmDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationDTO> evaluationList) {
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

    @Test
    void levelsTest() {
        SecuritySuitabilityPolicyType securitySuitabilityPolicyType = new SecuritySuitabilityPolicyType();

        CryptographicSuiteXmlWrapper cryptographicSuite = new CryptographicSuiteXmlWrapper(securitySuitabilityPolicyType);
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());

        assertEquals(Level.FAIL, cryptographicSuite.getLevel()); // default
        // inherited from default
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.FAIL, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.WARN, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel()); // default

        cryptographicSuite.setLevel(Level.IGNORE);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.WARN, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationTimeAfterPolicyUpdateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableDigestAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableEncryptionAlgorithmsLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAcceptableEncryptionAlgorithmsMinKeySizeLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.IGNORE, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());

        cryptographicSuite.setAlgorithmsExpirationDateLevel(Level.INFORM);
        assertEquals(Level.IGNORE, cryptographicSuite.getLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableDigestAlgoLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAcceptableEncryptionAlgoLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getMiniPublicKeySizeLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateLevel());
        assertEquals(Level.INFORM, cryptographicSuite.getAlgoExpirationDateAfterUpdateLevel());
    }

    private static class EvaluationDTO {

        private final String validityEnd;
        private final List<ParameterDTO> parameterList;

        public EvaluationDTO(final String validityEnd) {
            this.validityEnd = validityEnd;
            this.parameterList = null;
        }

        public EvaluationDTO(final String validityEnd, final List<ParameterDTO> parameterList) {
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
