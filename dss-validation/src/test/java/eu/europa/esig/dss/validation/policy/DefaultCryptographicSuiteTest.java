package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.EncryptionAlgorithmWithMinKeySize;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DefaultCryptographicSuiteTest {

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
            CryptographicSuite cryptographicSuite = factory.loadDefaultCryptographicSuite();
            args.add(Arguments.of(cryptographicSuite));
        }

        assertEquals(3, args.size()); // ensure number (+ xml and json crypto suites)

        return args.stream();
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableDigestAlgorithmsTest(CryptographicSuite cryptographicSuite) {
        List<DigestAlgorithm> acceptableDigestAlgorithms = cryptographicSuite.getAcceptableDigestAlgorithms();

        Set<DigestAlgorithm> expectedSet = new HashSet<>(Arrays.asList(
                DigestAlgorithm.MD5, DigestAlgorithm.SHA1,
                DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
                DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512,
                DigestAlgorithm.RIPEMD160, DigestAlgorithm.WHIRLPOOL));

        assertEquals(expectedSet, new HashSet<>(acceptableDigestAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableDigestAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<DigestAlgorithm, Date> digestAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableDigestAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<DigestAlgorithm, Date> expectedMap = new HashMap<>();

        calendar.set(2004, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.MD5, calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.SHA1, calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(DigestAlgorithm.SHA224, calendar.getTime());

        expectedMap.put(DigestAlgorithm.SHA256, null);
        expectedMap.put(DigestAlgorithm.SHA384, null);
        expectedMap.put(DigestAlgorithm.SHA512, null);
        expectedMap.put(DigestAlgorithm.SHA3_256, null);
        expectedMap.put(DigestAlgorithm.SHA3_384, null);
        expectedMap.put(DigestAlgorithm.SHA3_512, null);

        calendar.set(2014, Calendar.AUGUST, 1);
        expectedMap.put(DigestAlgorithm.RIPEMD160, calendar.getTime());

        calendar.set(2020, Calendar.DECEMBER, 1);
        expectedMap.put(DigestAlgorithm.WHIRLPOOL, calendar.getTime());

        assertEquals(expectedMap, new HashMap<>(digestAlgorithmsWithExpirationDates));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableEncryptionAlgorithmsTest(CryptographicSuite cryptographicSuite) {
        List<EncryptionAlgorithm> encryptionAlgorithms = cryptographicSuite.getAcceptableEncryptionAlgorithms();

        Set<EncryptionAlgorithm> expectedSet = new HashSet<>(Arrays.asList(
                EncryptionAlgorithm.DSA, EncryptionAlgorithm.RSA, EncryptionAlgorithm.RSASSA_PSS,
                EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.PLAIN_ECDSA));

        assertEquals(expectedSet, new HashSet<>(encryptionAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableEncryptionAlgorithmsWithMinKeySizesTest(CryptographicSuite cryptographicSuite) {
        List<EncryptionAlgorithmWithMinKeySize> encryptionAlgorithms = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithMinKeySizes();

        Set<EncryptionAlgorithmWithMinKeySize> expectedSet = new HashSet<>(Arrays.asList(
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1024),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 786),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 786),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 160),
                new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.PLAIN_ECDSA, 160)));

        assertEquals(expectedSet, new HashSet<>(encryptionAlgorithms));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getAcceptableEncryptionAlgorithmsWithExpirationDatesTest(CryptographicSuite cryptographicSuite) {
        Map<EncryptionAlgorithmWithMinKeySize, Date> encryptionAlgorithmsWithExpirationDates = cryptographicSuite.getAcceptableEncryptionAlgorithmsWithExpirationDates();

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        Map<EncryptionAlgorithmWithMinKeySize, Date> expectedMap = new HashMap<>();

        calendar.set(2015, Calendar.DECEMBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1024), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 1900), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.DSA, 3000), null);

        calendar.set(2010, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 786), calendar.getTime());

        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1024), calendar.getTime());

        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1536), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 1900), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSA, 3000), calendar.getTime());

        calendar.set(2010, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 786), calendar.getTime());

        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1024), calendar.getTime());

        calendar.set(2019, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1536), calendar.getTime());

        calendar.set(2029, Calendar.JANUARY, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 1900), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.RSASSA_PSS, 3000), null);

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 160), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 163), calendar.getTime());

        calendar.set(2021, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 224), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.ECDSA, 256), null);

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.PLAIN_ECDSA, 160), calendar.getTime());

        calendar.set(2012, Calendar.AUGUST, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.PLAIN_ECDSA, 163), calendar.getTime());

        calendar.set(2021, Calendar.OCTOBER, 1);
        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.PLAIN_ECDSA, 224), calendar.getTime());

        expectedMap.put(new EncryptionAlgorithmWithMinKeySize(EncryptionAlgorithm.PLAIN_ECDSA, 256), null);

        assertEquals(expectedMap, new HashMap<>(encryptionAlgorithmsWithExpirationDates));
    }

    @ParameterizedTest(name = "Policy {index} : {0}")
    @MethodSource("data")
    void getCryptographicSuiteUpdateDateTest(CryptographicSuite cryptographicSuite) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeZone(TimeZone.getTimeZone("UTC"));
        calendar.clear();

        calendar.set(2024, Calendar.OCTOBER, 13);

        assertEquals(calendar.getTime(), cryptographicSuite.getCryptographicSuiteUpdateDate());
    }

}
