package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonNumber;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.Test;

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

class CryptographicSuiteJsonWrapperTest {

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";
    private static final String QLENGTH = "glength";

    @Test
    void getAcceptableDigestAlgorithmsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptySet(), new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Set<DigestAlgorithm> expectedSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224));
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        expectedSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256));
        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));

        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        expectedSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

        assertEquals(expectedSet, new HashSet<>(cryptographicSuite.getAcceptableDigestAlgorithms()));
    }

    @Test
    void getAcceptableDigestAlgorithmsWithEmptyListTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.emptyList()));

        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);
        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        assertTrue(digestAlgorithmsWithExpirationDates.isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithInvalidDateTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "invalid-date"));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();
        assertTrue(digestAlgorithmsWithExpirationDates.isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithDuplicateAlgorithmsTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, "2030-01-01"));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null)); // Duplicate

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        // Expected: the last one (null expiration) overrides
        assertEquals(Collections.singletonMap(DigestAlgorithm.SHA256, null), digestAlgorithmsWithExpirationDates);
    }

    @Test
    void getAcceptableDigestAlgorithmsWithUnknownAlgorithmTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonObject unknownAlgorithm = new JsonObject(Map.of(
                new JsonString("Algorithm"), new JsonString("SHA999"),
                new JsonString("ExpirationDate"), new JsonString("2030-12-31")
        ));
        algorithmsList.add(unknownAlgorithm);

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        // silently skip unrecognized algorithms
        assertTrue(cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates().isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, "2029-01-01"));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_256, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_384, null));
        algorithmsList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA3_512, null));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<DigestAlgorithm, Date> expectedMap = new HashMap<>();

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(DigestAlgorithm.SHA224, calendar.getTime());

        expectedMap.put(DigestAlgorithm.SHA256, null);
        expectedMap.put(DigestAlgorithm.SHA384, null);
        expectedMap.put(DigestAlgorithm.SHA512, null);
        expectedMap.put(DigestAlgorithm.SHA3_256, null);
        expectedMap.put(DigestAlgorithm.SHA3_384, null);
        expectedMap.put(DigestAlgorithm.SHA3_512, null);

        assertEquals(expectedMap, new HashMap<>(digestAlgorithmsWithExpirationDates));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsEmptyList() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.emptyList()));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap))
        );

        List<EncryptionAlgorithm> algorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();
        assertTrue(algorithms.isEmpty(), "Expected no encryption algorithms for empty list.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsUnknownAlgorithmIgnored() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonObject unknownAlgorithm = new JsonObject(Map.of(
                new JsonString("Algorithm"), new JsonString("UNKNOWN_ALGO"),
                new JsonString("Evaluations"), new JsonArray(Collections.emptyList())
        ));
        algorithmsList.add(unknownAlgorithm);

        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), new JsonArray(algorithmsList));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        List<EncryptionAlgorithm> algorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();
        assertTrue(algorithms.isEmpty(), "Unknown algorithm should be ignored or not parsed.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        List<EncryptionAlgorithm> encryptionAlgorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();

        Set<EncryptionAlgorithm> expectedSet = new HashSet<>(Arrays.asList(
                EncryptionAlgorithm.DSA, EncryptionAlgorithm.RSA, EncryptionAlgorithm.RSASSA_PSS,
                EncryptionAlgorithm.ECDSA));

        assertEquals(expectedSet, new HashSet<>(encryptionAlgorithms));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesDuplicatesHandledCorrectly() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        // Duplicate entries for same algorithm
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(new ParameterType(1024, PLENGTH)))
        )));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType(null, Arrays.asList(new ParameterType(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        List<EncryptionAlgorithmWithMinKeySize> actual = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes();

        Set<EncryptionAlgorithmWithMinKeySize> expected = new HashSet<>(Arrays.asList(
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1024)));

        assertEquals(expected, new HashSet<>(actual));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesMissingParameter() {
        JsonObject badParam = new JsonObject(Map.of(
                new JsonString("Type"), new JsonString("pLength")
                // Missing actual value
        ));
        JsonObject algorithm = new JsonObject(Map.of(
                new JsonString("Algorithm"), new JsonString("DSA"),
                new JsonString("Evaluations"), new JsonArray(Arrays.asList(
                        new JsonObject(Map.of(
                                new JsonString("ExpirationDate"), new JsonString("2029-01-01"),
                                new JsonString("Parameters"), new JsonArray(Collections.singletonList(badParam))
                        ))
                ))
        ));

        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.singletonList(algorithm)));

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        List<EncryptionAlgorithmWithMinKeySize> result = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes();
        assertTrue(result.isEmpty(), "Malformed parameter should result in exclusion.");
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        List<EncryptionAlgorithmWithMinKeySize> encryptionAlgorithms = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes();

        Set<EncryptionAlgorithmWithMinKeySize> expectedSet = new HashSet<>(Arrays.asList(
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1900),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0)));

        assertEquals(expectedSet, new HashSet<>(encryptionAlgorithms));
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithExpirationDatesInvalidAndValidDateMixed() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("invalid-date", Arrays.asList(new ParameterType(1024, PLENGTH))),
                new EvaluationType("2035-12-31", Arrays.asList(new ParameterType(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<JsonString, JsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        Map<EncryptionAlgorithmWithMinKeySize, Date> result = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates();

        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.set(2035, Calendar.DECEMBER, 31);

        assertEquals(Collections.emptyMap(), result);
    }

    @Test
    void getAcceptableEncryptionAlgorithmsWithExpirationDatesTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, PLENGTH),
                        new ParameterType(200, QLENGTH)
                )),
                new EvaluationType(null, Arrays.asList(
                        new ParameterType(3000, PLENGTH),
                        new ParameterType(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA224, Arrays.asList(
                        new EvaluationType("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(1900, MODULES_LENGTH)
                )),
                new EvaluationType("2029-01-01", Arrays.asList(
                        new ParameterType(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<EncryptionAlgorithmWithMinKeySize, Date> expectedMap = new HashMap<>();

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1900), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 3000), null);

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 3000), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1900), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 3000), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 0), null);

        assertEquals(expectedMap, new HashMap<>(encryptionAlgorithmsWithExpirationDates));
    }

    @Test
    void getCryptographicSuiteUpdateDateTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
        assertNull(cryptographicSuite.getCryptographicSuiteUpdateDate());

        securitySuitabilityPolicyMap.put(new JsonString("PolicyIssueDate"), new JsonString("2024-10-13T00:00:00.000+01:00"));

        cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

    private JsonObject createDigestAlgorithmDefinition(DigestAlgorithm digestAlgorithm, String expirationTime) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(digestAlgorithm.getName()));
        if (digestAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(digestAlgorithm.getOid()));
        }
        if (digestAlgorithm.getUri() != null) {
            algorithmIdentifierMap.put(new JsonString("URI"), new JsonString(digestAlgorithm.getUri()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        List<JsonValue> evaluationList = new ArrayList<>();

        Map<JsonString, JsonValue> validityMap = new HashMap<>();
        if (expirationTime != null) {
            validityMap.put(new JsonString("End"), new JsonString(expirationTime));
        }
        Map<JsonString, JsonValue> evaluationObject = new HashMap<>();
        evaluationObject.put(new JsonString("Validity"), new JsonObject(validityMap));
        evaluationList.add(new JsonObject(evaluationObject));

        JsonArray evaluationArray = new JsonArray(evaluationList);
        algorithmMap.put(new JsonString("Evaluation"), evaluationArray);

        return new JsonObject(algorithmMap);
    }

    private JsonObject createEncryptionAlgorithmDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationType> evaluationTypes) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(encryptionAlgorithm.getName()));
        if (encryptionAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(encryptionAlgorithm.getOid()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        algorithmMap.put(new JsonString("Evaluation"), createEvaluationArray(evaluationTypes));

        return new JsonObject(algorithmMap);
    }

    private JsonObject createSignatureAlgorithmDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationType> evaluationTypes) {
        Map<JsonString, JsonValue> algorithmMap = new HashMap<>();

        Map<JsonString, JsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(signatureAlgorithm.getName()));
        if (signatureAlgorithm.getOid() != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(signatureAlgorithm.getOid()));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        algorithmMap.put(new JsonString("Evaluation"), createEvaluationArray(evaluationTypes));

        return new JsonObject(algorithmMap);
    }

    private JsonArray createEvaluationArray(List<EvaluationType> evaluationTypes) {
        List<JsonValue> evaluationList = new ArrayList<>();
        if (evaluationTypes != null && !evaluationTypes.isEmpty()) {
            for (EvaluationType evaluationType : evaluationTypes) {
                Map<JsonString, JsonValue> evaluationMap = new HashMap<>();
                Map<JsonString, JsonValue> validityMap = new HashMap<>();
                if (evaluationType.validityEnd != null) {
                    validityMap.put(new JsonString("End"), new JsonString(evaluationType.validityEnd));
                }
                evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
                if (evaluationType.parameterList != null && !evaluationType.parameterList.isEmpty()) {
                    List<JsonValue> paremeterList = new ArrayList<>();
                    for (ParameterType parameterType : evaluationType.parameterList) {
                        if (parameterType.minKeyLength != null) {
                            Map<JsonString, JsonValue> parameterMap = new HashMap<>();
                            parameterMap.put(new JsonString("Min"), new JsonNumber(parameterType.minKeyLength));
                            if (parameterType.parameterName != null) {
                                parameterMap.put(new JsonString("name"), new JsonString(parameterType.parameterName));
                            }
                            paremeterList.add(new JsonObject(parameterMap));
                        }
                    }
                    evaluationMap.put(new JsonString("Parameter"), new JsonArray(paremeterList));
                }
                evaluationList.add(new JsonObject(evaluationMap));
            }

        } else {
            // create empty validity
            Map<JsonString, JsonValue> evaluationMap = new HashMap<>();
            Map<JsonString, JsonValue> validityMap = new HashMap<>();
            evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
            evaluationList.add(new JsonObject(evaluationMap));
        }
        return new JsonArray(evaluationList);
    }

    @Test
    void levelsTest() {
        Map<JsonString, JsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonWrapper cryptographicSuite = new CryptographicSuiteJsonWrapper(new JsonObjectWrapper(jsonObject));
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

    private static class EvaluationType {

        private final String validityEnd;
        private final List<ParameterType> parameterList;

        public EvaluationType(final String validityEnd, final List<ParameterType> parameterList) {
            this.validityEnd = validityEnd;
            this.parameterList = parameterList;
        }

    }

    private static class ParameterType {
        private final Integer minKeyLength;
        private final String parameterName;

        public ParameterType(final Integer minKeyLength, final String parameterName) {
            this.minKeyLength = minKeyLength;
            this.parameterName = parameterName;
        }
    }

}
