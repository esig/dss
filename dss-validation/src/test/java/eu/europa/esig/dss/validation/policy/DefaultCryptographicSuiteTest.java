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
import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteCatalogue;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteEvaluation;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteParameter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class DefaultCryptographicSuiteTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd";

    private static final String MODULES_LENGTH = "moduluslength";
    private static final String PLENGTH = "plength";

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();

        ServiceLoader<ValidationPolicyFactory> valPolicyLoader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> valPolicyOptions = valPolicyLoader.iterator();
        while (valPolicyOptions.hasNext()) {
            ValidationPolicyFactory factory = valPolicyOptions.next();
            ValidationPolicy validationPolicy = factory.loadDefaultValidationPolicy();
            CryptographicSuite cryptographicSuite = validationPolicy.getSignatureCryptographicConstraint(Context.SIGNATURE);
            args.add(Arguments.of(cryptographicSuite));
        }

        assertEquals(1, args.size());

        ServiceLoader<CryptographicSuiteFactory> cryptoSuiteLoader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> cryptoSuiteOptions = cryptoSuiteLoader.iterator();
        while (cryptoSuiteOptions.hasNext()) {
            CryptographicSuiteFactory factory = cryptoSuiteOptions.next();
            CryptographicSuiteCatalogue cryptographicSuiteCatalogue = factory.loadDefaultCryptographicSuite();
            args.add(Arguments.of(cryptographicSuiteCatalogue.getCryptographicSuite()));
        }

        assertEquals(3, args.size()); // ensure number (default policy + xml and json crypto suites)

        return args.stream();
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<DigestAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();

        Map<DigestAlgorithm, Set<CryptographicSuiteEvaluation>> expectedMap = new EnumMap<>(DigestAlgorithm.class);

        expectedMap.put(DigestAlgorithm.MD5, createEvaluations(new EvaluationDTO("2004-08-01")));
        expectedMap.put(DigestAlgorithm.SHA1, createEvaluations(new EvaluationDTO("2012-08-01")));
        expectedMap.put(DigestAlgorithm.SHA224, createEvaluations(new EvaluationDTO("2029-01-01")));

        expectedMap.put(DigestAlgorithm.SHA256, createEvaluations());
        expectedMap.put(DigestAlgorithm.SHA384, createEvaluations());
        expectedMap.put(DigestAlgorithm.SHA512, createEvaluations());
        expectedMap.put(DigestAlgorithm.SHA3_256, createEvaluations());
        expectedMap.put(DigestAlgorithm.SHA3_384, createEvaluations());
        expectedMap.put(DigestAlgorithm.SHA3_512, createEvaluations());

        expectedMap.put(DigestAlgorithm.RIPEMD160, createEvaluations(new EvaluationDTO("2014-08-01")));
        expectedMap.put(DigestAlgorithm.WHIRLPOOL, createEvaluations(new EvaluationDTO("2020-12-01")));

        assertAlgorithmsEquals(expectedMap, acceptableDigestAlgorithms);
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableSignatureAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> acceptableSignatureAlgorithms = cryptographicSuite.getAcceptableSignatureAlgorithms();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<SignatureAlgorithm, Set<CryptographicSuiteEvaluation>> expectedMap = new EnumMap<>(SignatureAlgorithm.class);

        expectedMap.put(SignatureAlgorithm.RSA_MD5, createEvaluations(
                new EvaluationDTO("2004-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2004-08-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2004-08-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2004-08-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2004-08-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA224, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA256, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA384, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA512, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA3_256, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA3_384, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SHA3_512, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2035-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_RIPEMD160, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));

        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA1_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA224_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA3_256_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA3_384_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.RSA_SSA_PSS_SHA3_512_MGF1, createEvaluations(
                new EvaluationDTO("2010-08-01", Collections.singletonList(new ParameterDTO(786, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1024, MODULES_LENGTH))),
                new EvaluationDTO("2019-10-01", Collections.singletonList(new ParameterDTO(1536, MODULES_LENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, MODULES_LENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, MODULES_LENGTH)))
        ));

        expectedMap.put(SignatureAlgorithm.DSA_SHA1, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA224, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA256, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA384, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA512, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA3_256, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA3_384, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.DSA_SHA3_512, createEvaluations(
                new EvaluationDTO("2015-12-01", Collections.singletonList(new ParameterDTO(1024, PLENGTH))),
                new EvaluationDTO("2027-01-01", Collections.singletonList(new ParameterDTO(1900, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(3000, PLENGTH)))
        ));

        expectedMap.put(SignatureAlgorithm.ECDSA_SHA1, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA224, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA256, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA384, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA512, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA3_256, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA3_384, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_SHA3_512, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.ECDSA_RIPEMD160, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));

        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA1, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA224, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2029-01-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA256, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA384, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA512, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA3_256, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA3_384, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_SHA3_512, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2021-10-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO(null, Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));
        expectedMap.put(SignatureAlgorithm.PLAIN_ECDSA_RIPEMD160, createEvaluations(
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(160, PLENGTH))),
                new EvaluationDTO("2012-08-01", Collections.singletonList(new ParameterDTO(163, PLENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(224, PLENGTH))),
                new EvaluationDTO("2014-08-01", Collections.singletonList(new ParameterDTO(256, PLENGTH)))
        ));

        assertAlgorithmsEquals(expectedMap, acceptableSignatureAlgorithms);
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getCryptographicSuiteUpdateDateTest(CryptographicSuite cryptographicSuite) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        calendar.set(2026, Calendar.FEBRUARY, 1);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

    private Set<CryptographicSuiteEvaluation> createEvaluations(EvaluationDTO... evaluationList) {
        Set<CryptographicSuiteEvaluation> result = new HashSet<>();
        if (evaluationList != null && evaluationList.length != 0) {
            for (EvaluationDTO evaluationDTO : evaluationList) {
                CryptographicSuiteEvaluation evaluation = new CryptographicSuiteEvaluation();
                evaluation.setValidityEnd(toDate(evaluationDTO.validityEnd));
                evaluation.setParameterList(getParameters(evaluationDTO));
                evaluation.setAlgorithmUsage(getUsage());
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

    private List<CryptographicSuiteParameter> getParameters(EvaluationDTO evaluationDTO) {
        List<CryptographicSuiteParameter> parameters = new ArrayList<>();
        if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
            for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                CryptographicSuiteParameter parameter = new CryptographicSuiteParameter();
                parameter.setMin(parameterDTO.minKeyLength);
                parameter.setName(parameterDTO.parameterName);
                parameters.add(parameter);
            }
        }
        return parameters;
    }

    private List<CryptographicSuiteAlgorithmUsage> getUsage() {
        return Collections.emptyList();
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

    private <T> void assertAlgorithmsEquals(Map<T, Set<CryptographicSuiteEvaluation>> mapOne, Map<T, Set<CryptographicSuiteEvaluation>> mapTwo) {
        if (mapOne == mapTwo)
            return;

        assertEquals(mapOne.size(), mapTwo.size());

        for (Map.Entry<T, Set<CryptographicSuiteEvaluation>> e : mapOne.entrySet()) {
            T key = e.getKey();
            Set<CryptographicSuiteEvaluation> value = e.getValue();
            if (value == null) {
                assertTrue(mapTwo.get(key) == null && mapTwo.containsKey(key));
            } else {
                assertEquals(value.size(), mapTwo.get(key).size(), key.toString());
                for (CryptographicSuiteEvaluation cse : value) {
                    Set<CryptographicSuiteEvaluation> valueTwo = mapTwo.get(key);
                    assertTrue(valueTwo.stream().anyMatch(cseTwo -> checkEvaluationEquals(cse, cseTwo)),
                            String.format("Algo : %s\nFirst set :  %s\nSecond set : %s", key, value, valueTwo));
                }
            }
        }
    }

    private boolean checkEvaluationEquals(CryptographicSuiteEvaluation evaluationOne, CryptographicSuiteEvaluation evaluationTwo) {
        // NOTE: we compare manually because default XML Validation Policy does not create all parameters, defined in the cryptographic suites
        return Objects.equals(evaluationOne.getAlgorithmUsage(), evaluationTwo.getAlgorithmUsage()) &&
                Objects.equals(evaluationOne.getValidityStart(), evaluationTwo.getValidityStart()) &&
                Objects.equals(evaluationOne.getValidityEnd(), evaluationTwo.getValidityEnd()) &&
                Objects.equals(filterSupportedParameters(evaluationOne.getParameterList()), filterSupportedParameters(evaluationTwo.getParameterList()));
    }

    private Set<CryptographicSuiteParameter> filterSupportedParameters(Collection<CryptographicSuiteParameter> parameters) {
        return parameters.stream().filter(p ->
                        CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER.equals(p.getName()) || CryptographicSuiteUtils.PLENGTH_PARAMETER.equals(p.getName()))
                .collect(Collectors.toSet());
    }

}
