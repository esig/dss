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
package eu.europa.esig.dss.policy.crypto.json;

import com.github.erosb.jsonsKema.IJsonString;
import com.github.erosb.jsonsKema.IJsonValue;
import com.github.erosb.jsonsKema.JsonArray;
import com.github.erosb.jsonsKema.JsonNumber;
import com.github.erosb.jsonsKema.JsonObject;
import com.github.erosb.jsonsKema.JsonString;
import com.github.erosb.jsonsKema.JsonValue;
import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.enumerations.CryptographicSuiteRecommendation;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteAlgorithm;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteEvaluation;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteMetadata;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteParameter;
import eu.europa.esig.json.JsonObjectWrapper;
import org.junit.jupiter.api.Test;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicSuiteJsonCatalogueTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd";
    private static final String DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ssXXX";

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";
    private static final String QLENGTH = "glength";

    @Test
    void getAcceptableDigestAlgorithmsTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptyList(), cryptographicSuite.buildAlgorithmList());

        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));
        assertEquals(Collections.emptyList(), cryptographicSuite.buildAlgorithmList());

        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        List<CryptographicSuiteAlgorithm> expectedList = new ArrayList<>();

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA256, null));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO(null, null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA384, null));
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA512, null));
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA3_256, null));
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA3_384, null));
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA3_512, null));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

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
    void getAcceptableDigestAlgorithmsWithInvalidDateTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA256, "invalid-date"));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        assertTrue(cryptographicSuite.buildAlgorithmList().isEmpty());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithDuplicateAlgorithmsTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.singletonList(
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2021-01-01")
        )));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("GMT+0"));
        calendar.clear();

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // duplicate entries test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2029-01-01")
        )));

        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // opposite test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2029-01-01"),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2021-01-01")
        )));

        expected = new ArrayList<>();

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2021-01-01", null)
        )));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // null test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2029-01-01"),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, null)
        )));

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

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // opposite null test

        securitySuitabilityPolicyMap = new HashMap<>();

        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Arrays.asList(
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, null),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2021-01-01"),
                createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2029-01-01")
        )));

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

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap)));
        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithUnknownAlgorithmTest() {
        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createAlgorithmJsonDefinition("SHA999", null, null,
                Collections.singletonList(new EvaluationDTO("2030-12-31", null))));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName("SHA999");
        algorithm.setAlgorithmIdentifierOIDs(Collections.emptyList());
        algorithm.setAlgorithmIdentifierURIs(Collections.emptyList());
        algorithm.setEvaluationList(createEvaluations(Collections.singletonList(
                new EvaluationDTO("2030-12-31", null)
        )));
        algorithm.setInformationTextList(Collections.emptyList());

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));
        // return all extracted values
        assertEquals(Collections.singletonList(algorithm), cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableDigestAlgorithmsWithStartDatesTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        List<JsonValue> algorithmsList = new ArrayList<>();
        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);

        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA224, "2000-01-01", "2029-01-01"));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        List<CryptographicSuiteAlgorithm> expectedList = new ArrayList<>();

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224, Collections.singletonList(
                new EvaluationDTO("2000-01-01", "2029-01-01", null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());

        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA256, "2000-01-01", null));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        expectedList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256, Collections.singletonList(
                new EvaluationDTO("2000-01-01", null, null)
        )));

        assertEquals(expectedList, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsEmptyList() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), new JsonArray(Collections.emptyList()));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(securitySuitabilityPolicyMap))
        );

        assertTrue(cryptographicSuite.buildAlgorithmList().isEmpty(), "Expected no encryption algorithms for empty list.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsUnknownAlgorithmIgnored() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        algorithmsList.add(createAlgorithmJsonDefinition("UNKNOWN_ALGO", null, null,
                Collections.emptyList()));

        Map<IJsonString, IJsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), new JsonArray(algorithmsList));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName("UNKNOWN_ALGO");
        algorithm.setAlgorithmIdentifierOIDs(Collections.emptyList());
        algorithm.setAlgorithmIdentifierURIs(Collections.emptyList());
        algorithm.setEvaluationList(createEvaluations(Collections.emptyList()));
        algorithm.setInformationTextList(Collections.emptyList());

        // return all extracted values
        assertEquals(Collections.singletonList(algorithm), cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

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
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.emptyList())
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithMinKeySizesDuplicatesHandledCorrectly() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        // Duplicate entries for same algorithm
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH)))
        )));
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<IJsonString, IJsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        List<CryptographicSuiteAlgorithm> expected = new ArrayList<>();

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH)))
        )));

        expected.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(2048, PLENGTH)))
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA256, "2029-01-01"));
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

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
        List<JsonValue> algorithmsList = new ArrayList<>();

        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Collections.singletonList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(null, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<IJsonString, IJsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA256, "2029-01-01"));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(policyMap)));

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
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2029-01-01", Collections.emptyList())
                )
        ));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.ECDSA_SHA256, Collections.emptyList()));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.RSA_SHA224, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.RSASSA_PSS, Arrays.asList(
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(1900, MODULES_LENGTH)
                )),
                new EvaluationDTO("2029-01-01", Collections.singletonList(
                        new ParameterDTO(3000, MODULES_LENGTH)
                )))
        ));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

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
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA512, "2029-01-01"));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));
        expected.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512, Collections.singletonList(
                new EvaluationDTO("2029-01-01", null)
        )));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithExpirationDatesInvalidAndValidDateMixed() {
        List<JsonValue> algorithmsList = new ArrayList<>();

        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.DSA_SHA256, Arrays.asList(
                new EvaluationDTO("invalid-date", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2035-12-31", Collections.singletonList(new ParameterDTO(2048, PLENGTH)))
        )));

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        Map<IJsonString, IJsonValue> policyMap = new HashMap<>();
        policyMap.put(new JsonString("Algorithm"), algorithmsArray);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(
                new JsonObjectWrapper(new JsonObject(policyMap))
        );

        assertTrue(cryptographicSuite.buildAlgorithmList().isEmpty(), "Invalid date format shall result to a failure.");
    }

    @Test
    void getAcceptableSignatureAlgorithmsWithStartDatesTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();

        List<JsonValue> algorithmsList = new ArrayList<>();
        algorithmsList.add(createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm.DSA, Arrays.asList(
                new EvaluationDTO("2020-01-01", "2029-01-01", Arrays.asList(
                        new ParameterDTO(1900, PLENGTH),
                        new ParameterDTO(200, QLENGTH)
                )),
                new EvaluationDTO(null, Arrays.asList(
                        new ParameterDTO(3000, PLENGTH),
                        new ParameterDTO(250, QLENGTH)
                )))
        ));
        algorithmsList.add(createSignatureAlgorithmJsonDefinition(SignatureAlgorithm.ECDSA_SHA224, Collections.singletonList(
                        new EvaluationDTO("2000-01-01", "2029-01-01", Collections.emptyList())
                )
        ));

        // Add DigestAlgorithm definition
        algorithmsList.add(createDigestAlgorithmJsonDefinition(DigestAlgorithm.SHA512, "2010-01-01", "2029-01-01"));

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

        JsonArray algorithmsArray = new JsonArray(algorithmsList);
        securitySuitabilityPolicyMap.put(new JsonString("Algorithm"), algorithmsArray);
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        assertEquals(expected, cryptographicSuite.buildAlgorithmList());
    }

    @Test
    void getCryptographicSuiteUpdateDateTest() {
        Map<IJsonString, IJsonValue> securitySuitabilityPolicyMap = new HashMap<>();
        JsonObject jsonObject = new JsonObject(securitySuitabilityPolicyMap);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

        CryptographicSuiteMetadata metadata = cryptographicSuite.buildMetadata();
        assertNotNull(metadata);
        assertNull(metadata.getPolicyIssueDate());

        securitySuitabilityPolicyMap.put(new JsonString("PolicyIssueDate"), new JsonString("2024-10-13T00:00:00.000+01:00"));

        cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(jsonObject));

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
        Map<IJsonString, IJsonValue> policyName = new HashMap<>();
        policyName.put(new JsonString("Name"), new JsonString("Test Policy"));
        policyName.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.3.4.5"));
        policyName.put(new JsonString("URI"), new JsonString("http://policy.example.com"));

        Map<IJsonString, IJsonValue> publisher = new HashMap<>();
        publisher.put(new JsonString("Name"), new JsonString("Example Publisher"));
        publisher.put(new JsonString("Address"), new JsonString("123 Example Street"));
        publisher.put(new JsonString("URI"), new JsonString("http://publisher.example.com"));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("PolicyName"), new JsonObject(policyName));
        root.put(new JsonString("Publisher"), new JsonObject(publisher));
        root.put(new JsonString("PolicyIssueDate"), new JsonString("2025-01-01T12:00:00+00:00"));
        root.put(new JsonString("NextUpdate"), new JsonString("2025-06-01T12:00:00+00:00"));
        root.put(new JsonString("Usage"), new JsonString("general"));
        root.put(new JsonString("version"), new JsonString("2"));
        root.put(new JsonString("lang"), new JsonString("fr"));
        root.put(new JsonString("id"), new JsonString("policy-123"));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));

        CryptographicSuiteMetadata metadata = cryptographicSuite.buildMetadata();

        assertEquals("Test Policy", metadata.getPolicyName());
        assertEquals("1.2.3.4.5", metadata.getPolicyOID());
        assertEquals("http://policy.example.com", metadata.getPolicyURI());
        assertEquals("Example Publisher", metadata.getPublisherName());
        assertEquals("123 Example Street", metadata.getPublisherAddress());
        assertEquals("http://publisher.example.com", metadata.getPublisherURI());
        assertEquals(toDateTime("2025-01-01T12:00:00+00:00"), metadata.getPolicyIssueDate());
        assertEquals(toDateTime("2025-06-01T12:00:00+00:00"), metadata.getNextUpdate());
        assertEquals("general", metadata.getUsage());
        assertEquals("2", metadata.getVersion());
        assertEquals("fr", metadata.getLang());
        assertEquals("policy-123", metadata.getId());
    }

    @Test
    void testBuildMetadataWithMissingOptionalFields() {
        Map<IJsonString, IJsonValue> policyName = new HashMap<>();
        policyName.put(new JsonString("Name"), new JsonString("Minimal Policy"));

        Map<IJsonString, IJsonValue> publisher = new HashMap<>();
        publisher.put(new JsonString("Name"), new JsonString("Minimal Publisher"));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("PolicyName"), new JsonObject(policyName));
        root.put(new JsonString("Publisher"), new JsonObject(publisher));
        root.put(new JsonString("PolicyIssueDate"), new JsonString("2025-01-01T12:00:00+00:00"));

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));

        CryptographicSuiteMetadata metadata = cryptographicSuite.buildMetadata();

        assertEquals("Minimal Policy", metadata.getPolicyName());
        assertNull(metadata.getPolicyOID());
        assertNull(metadata.getPolicyURI());
        assertEquals("Minimal Publisher", metadata.getPublisherName());
        assertNull(metadata.getPublisherAddress());
        assertNull(metadata.getPublisherURI());
        assertEquals(toDateTime("2025-01-01T12:00:00+00:00"), metadata.getPolicyIssueDate());
        assertNull(metadata.getNextUpdate());
        assertNull(metadata.getUsage());
        assertEquals("1", metadata.getVersion()); // default
        assertEquals("en", metadata.getLang());   // default
        assertNull(metadata.getId());
    }

    @Test
    void testSingleAlgorithmWithFullDetails() {
        Map<IJsonString, IJsonValue> algorithmIdentifier = new HashMap<>();
        algorithmIdentifier.put(new JsonString("Name"), new JsonString("SHA256withRSA"));
        algorithmIdentifier.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.840.113549.1.1.11"));
        algorithmIdentifier.put(new JsonString("URI"), new JsonString("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"));

        Map<IJsonString, IJsonValue> parameter = new HashMap<>();
        parameter.put(new JsonString("name"), new JsonString("moduluslength"));
        parameter.put(new JsonString("Min"), new JsonNumber(2048));
        parameter.put(new JsonString("Max"), new JsonNumber(4096));

        Map<IJsonString, IJsonValue> validity = new HashMap<>();
        validity.put(new JsonString("Start"), new JsonString("2020-01-01"));
        validity.put(new JsonString("End"), new JsonString("2030-01-01"));

        Map<IJsonString, IJsonValue> evaluation = new HashMap<>();
        evaluation.put(new JsonString("Validity"), new JsonObject(validity));
        evaluation.put(new JsonString("AlgorithmUsage"), new JsonString("http://uri.etsi.org/19322/sign_data"));
        evaluation.put(new JsonString("Recommendation"), new JsonString("R"));
        evaluation.put(new JsonString("Parameter"), new JsonArray(Collections.singletonList(new JsonObject(parameter))));

        JsonArray evaluations = new JsonArray(Collections.singletonList(new JsonObject(evaluation)));

        Map<IJsonString, IJsonValue> information = new HashMap<>();
        information.put(new JsonString("Text"), new JsonArray(Collections.singletonList(new JsonString("Widely used secure algorithm"))));

        Map<IJsonString, IJsonValue> algorithm = new HashMap<>();
        algorithm.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifier));
        algorithm.put(new JsonString("Evaluation"), evaluations);
        algorithm.put(new JsonString("Information"), new JsonObject(information));

        JsonArray algorithms = new JsonArray(Collections.singletonList(new JsonObject(algorithm)));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteAlgorithm rsa = result.get(0);
        assertEquals("SHA256withRSA", rsa.getAlgorithmIdentifierName());
        assertEquals(Collections.singletonList("1.2.840.113549.1.1.11"), rsa.getAlgorithmIdentifierOIDs());
        assertEquals(Collections.singletonList("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), rsa.getAlgorithmIdentifierURIs());
        assertEquals(Collections.singletonList("Widely used secure algorithm"), rsa.getInformationTextList());
        assertEquals(1, rsa.getEvaluationList().size());

        CryptographicSuiteEvaluation eval = rsa.getEvaluationList().get(0);
        assertEquals(eval.getParameterList().size(), 1);

        CryptographicSuiteParameter par = eval.getParameterList().get(0);
        assertEquals("moduluslength", par.getName());
        assertEquals(2048, par.getMin());
        assertEquals(4096, par.getMax());

        assertEquals(toDate("2020-01-01"), eval.getValidityStart());
        assertEquals(toDate("2030-01-01"), eval.getValidityEnd());
        assertEquals(Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_DATA), eval.getAlgorithmUsage());
        assertEquals(CryptographicSuiteRecommendation.RECOMMENDED, eval.getRecommendation());
    }

    @Test
    void testAlgorithmWithoutOptionalFields() {
        Map<IJsonString, IJsonValue> algorithmIdentifier = new HashMap<>();
        algorithmIdentifier.put(new JsonString("Name"), new JsonString("SHA256"));
        algorithmIdentifier.put(new JsonString("ObjectIdentifier"), new JsonString("2.16.840.1.101.3.4.2.1"));

        Map<IJsonString, IJsonValue> algorithm = new HashMap<>();
        algorithm.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifier));

        JsonArray algorithms = new JsonArray(Collections.singletonList(new JsonObject(algorithm)));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

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
        Map<IJsonString, IJsonValue> id1 = new HashMap<>();
        id1.put(new JsonString("Name"), new JsonString("RSA"));
        id1.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.840.113549.1.1.1"));

        Map<IJsonString, IJsonValue> algorithmOne = new HashMap<>();
        algorithmOne.put(new JsonString("AlgorithmIdentifier"), new JsonObject(id1));

        Map<IJsonString, IJsonValue> id2 = new HashMap<>();
        id2.put(new JsonString("Name"), new JsonString("ECDSA"));
        id2.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.840.10045.2.1"));

        Map<IJsonString, IJsonValue> algorithmTwo = new HashMap<>();
        algorithmTwo.put(new JsonString("AlgorithmIdentifier"), new JsonObject(id2));

        JsonArray algorithms = new JsonArray(Arrays.asList(new JsonObject(algorithmOne), new JsonObject(algorithmTwo)));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

        assertEquals(2, result.size());
        assertEquals(Arrays.asList("RSA", "ECDSA"), result.stream().map(CryptographicSuiteAlgorithm::getAlgorithmIdentifierName).collect(Collectors.toList()));
    }

    @Test
    void testUnknownAlgorithmUsageUriResultsInNull() {
        Map<IJsonString, IJsonValue> algorithmIdentifier = new HashMap<>();
        algorithmIdentifier.put(new JsonString("Name"), new JsonString("TestAlg"));
        algorithmIdentifier.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.3"));

        Map<IJsonString, IJsonValue> eval = new HashMap<>();
        eval.put(new JsonString("AlgorithmUsage"), new JsonString("http://uri.etsi.org/19322/unknown_usage"));
        eval.put(new JsonString("Recommendation"), new JsonString("X"));

        JsonArray evaluations = new JsonArray(Collections.singletonList(new JsonObject(eval)));

        Map<IJsonString, IJsonValue> algorithm = new HashMap<>();
        algorithm.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifier));
        algorithm.put(new JsonString("Evaluation"), evaluations);

        JsonArray algorithms = new JsonArray(Collections.singletonList(new JsonObject(algorithm)));

        Map<IJsonString, JsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteEvaluation evaluation = result.get(0).getEvaluationList().get(0);
        assertTrue(evaluation.getAlgorithmUsage().isEmpty());
        assertNull(evaluation.getRecommendation());
    }

    @Test
    void testEvaluationWithoutValidityDates() {
        Map<IJsonString, IJsonValue> algorithmIdentifier = new HashMap<>();
        algorithmIdentifier.put(new JsonString("Name"), new JsonString("TestAlg"));
        algorithmIdentifier.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.3"));

        Map<IJsonString, IJsonValue> validity = new HashMap<>(); // no start, no end

        Map<IJsonString, IJsonValue> eval = new HashMap<>();
        eval.put(new JsonString("Validity"), new JsonObject(validity));

        JsonArray evaluations = new JsonArray(Collections.singletonList(new JsonObject(eval)));

        Map<IJsonString, IJsonValue> algorithm = new HashMap<>();
        algorithm.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifier));
        algorithm.put(new JsonString("Evaluation"), evaluations);

        JsonArray algorithms = new JsonArray(Collections.singletonList(new JsonObject(algorithm)));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

        assertEquals(1, result.size());
        CryptographicSuiteEvaluation evaluation = result.get(0).getEvaluationList().get(0);
        assertNull(evaluation.getValidityStart());
        assertNull(evaluation.getValidityEnd());
    }

    @Test
    void testParameterWithOnlyMinOrMax() {
        Map<IJsonString, IJsonValue> algorithmIdentifier = new HashMap<>();
        algorithmIdentifier.put(new JsonString("Name"), new JsonString("TestAlg"));
        algorithmIdentifier.put(new JsonString("ObjectIdentifier"), new JsonString("1.2.3"));

        Map<IJsonString, IJsonValue> par1 = new HashMap<>();
        par1.put(new JsonString("name"), new JsonString("p1"));
        par1.put(new JsonString("Min"), new JsonNumber(1024));

        Map<IJsonString, IJsonValue> par2 = new HashMap<>();
        par2.put(new JsonString("name"), new JsonString("p2"));
        par2.put(new JsonString("Max"), new JsonNumber(8192));

        Map<IJsonString, IJsonValue> eval = new HashMap<>();
        eval.put(new JsonString("Validity"), new JsonObject(new HashMap<>()));
        eval.put(new JsonString("Parameter"), new JsonArray(Arrays.asList(new JsonObject(par1), new JsonObject(par2))));

        JsonArray evaluations = new JsonArray(Collections.singletonList(new JsonObject(eval)));

        Map<IJsonString, IJsonValue> algorithm = new HashMap<>();
        algorithm.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifier));
        algorithm.put(new JsonString("Evaluation"), evaluations);

        JsonArray algorithms = new JsonArray(Collections.singletonList(new JsonObject(algorithm)));

        Map<IJsonString, IJsonValue> root = new HashMap<>();
        root.put(new JsonString("Algorithm"), algorithms);

        CryptographicSuiteJsonCatalogue cryptographicSuite = new CryptographicSuiteJsonCatalogue(new JsonObjectWrapper(new JsonObject(root)));
        List<CryptographicSuiteAlgorithm> result = cryptographicSuite.buildAlgorithmList();

        assertEquals(1, result.size());
        List<CryptographicSuiteParameter> params = result.get(0).getEvaluationList().get(0).getParameterList();
        assertEquals(2, params.size());
        assertEquals(1024, params.get(0).getMin());
        assertNull(params.get(0).getMax());
        assertNull(params.get(1).getMin());
        assertEquals(8192, params.get(1).getMax());
    }

    private JsonObject createDigestAlgorithmJsonDefinition(DigestAlgorithm digestAlgorithm, String expirationTime) {
        return createAlgorithmJsonDefinition(digestAlgorithm.getName(), digestAlgorithm.getOid(), digestAlgorithm.getUri(),
                Collections.singletonList(new EvaluationDTO(expirationTime, null)));
    }

    private JsonObject createDigestAlgorithmJsonDefinition(DigestAlgorithm digestAlgorithm, String startTime, String expirationTime) {
        return createAlgorithmJsonDefinition(digestAlgorithm.getName(), digestAlgorithm.getOid(), digestAlgorithm.getUri(),
                Collections.singletonList(new EvaluationDTO(startTime, expirationTime, null)));
    }

    private JsonObject createEncryptionAlgorithmJsonDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationDTO> evaluationDTOS) {
        return createAlgorithmJsonDefinition(encryptionAlgorithm.getName(), encryptionAlgorithm.getOid(), null, evaluationDTOS);
    }

    private JsonObject createSignatureAlgorithmJsonDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationDTO> evaluationDTOS) {
        return createAlgorithmJsonDefinition(signatureAlgorithm.getName(), signatureAlgorithm.getOid(), signatureAlgorithm.getUri(), evaluationDTOS);
    }

    private JsonObject createAlgorithmJsonDefinition(String algorithmName, String algorithmOid, String algorithmUri, List<EvaluationDTO> evaluationDTOS) {
        Map<IJsonString, IJsonValue> algorithmMap = new HashMap<>();

        Map<IJsonString, IJsonValue> algorithmIdentifierMap = new HashMap<>();
        algorithmIdentifierMap.put(new JsonString("Name"), new JsonString(algorithmName));
        if (algorithmOid != null) {
            algorithmIdentifierMap.put(new JsonString("ObjectIdentifier"), new JsonString(algorithmOid));
        }
        if (algorithmUri != null) {
            algorithmIdentifierMap.put(new JsonString("URI"), new JsonString(algorithmUri));
        }

        algorithmMap.put(new JsonString("AlgorithmIdentifier"), new JsonObject(algorithmIdentifierMap));

        algorithmMap.put(new JsonString("Evaluation"), createEvaluationArray(evaluationDTOS));

        return new JsonObject(algorithmMap);
    }

    private JsonArray createEvaluationArray(List<EvaluationDTO> evaluationDTOS) {
        List<JsonValue> evaluationList = new ArrayList<>();
        if (evaluationDTOS != null && !evaluationDTOS.isEmpty()) {
            for (EvaluationDTO evaluationDTO : evaluationDTOS) {
                Map<IJsonString, IJsonValue> evaluationMap = new HashMap<>();
                Map<IJsonString, IJsonValue> validityMap = new HashMap<>();
                if (evaluationDTO.validityStart != null) {
                    validityMap.put(new JsonString("Start"), new JsonString(evaluationDTO.validityStart));
                }
                if (evaluationDTO.validityEnd != null) {
                    validityMap.put(new JsonString("End"), new JsonString(evaluationDTO.validityEnd));
                }
                evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
                if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
                    List<JsonValue> paremeterList = new ArrayList<>();
                    for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                        Map<IJsonString, IJsonValue> parameterMap = new HashMap<>();
                        if (parameterDTO.minKeyLength != null) {
                            parameterMap.put(new JsonString("Min"), new JsonNumber(parameterDTO.minKeyLength));
                        }
                        if (parameterDTO.parameterName != null) {
                            parameterMap.put(new JsonString("name"), new JsonString(parameterDTO.parameterName));
                        }
                        paremeterList.add(new JsonObject(parameterMap));
                    }
                    evaluationMap.put(new JsonString("Parameter"), new JsonArray(paremeterList));
                }
                evaluationList.add(new JsonObject(evaluationMap));
            }

        } else {
            // create empty validity
            Map<IJsonString, IJsonValue> evaluationMap = new HashMap<>();
            Map<IJsonString, IJsonValue> validityMap = new HashMap<>();
            evaluationMap.put(new JsonString("Validity"), new JsonObject(validityMap));
            evaluationList.add(new JsonObject(evaluationMap));
        }
        return new JsonArray(evaluationList);
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
