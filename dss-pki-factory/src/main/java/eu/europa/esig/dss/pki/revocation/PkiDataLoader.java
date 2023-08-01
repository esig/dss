package eu.europa.esig.dss.pki.revocation;

import eu.europa.esig.dss.pki.exception.Error500Exception;
import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.revocation.enums.PkiDataLoaderType;
import eu.europa.esig.dss.pki.revocation.enums.TriFunction;
import eu.europa.esig.dss.pki.service.*;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * A class responsible for loading PKI data from different sources such as certificates, CRLs, OCSP responses, and keystore.
 * It implements the DataLoader interface from the DSS SPI for fetching data.
 * The class provides methods for fetching data based on the provided URL strings and handling various types of PKI data retrieval.
 */
public class PkiDataLoader implements DataLoader {
    private static final Logger LOG = LoggerFactory.getLogger(PkiDataLoader.class);

    private final CertificateEntityService certService = GenericFactory.getInstance().create(CertificateEntityService.class);
    private final CRLGenerator crlGenerator = GenericFactory.getInstance().create(CRLGenerator.class);
    private final KeystoreGenerator keystoreGenerator = GenericFactory.getInstance().create(KeystoreGenerator.class);
    private final TimestampGenerator timestampGenerator = GenericFactory.getInstance().create(TimestampGenerator.class);

    private final ErrorGenerator errorGenerator = new ErrorGenerator();


    @Override
    public byte[] get(final String s) {
        return PkiDataLoaderType.getType(s).getFunction().apply(this, s).getData();
    }

    @Override
    public DataAndUrl get(final List<String> urlStrings) {
        if (urlStrings == null || urlStrings.isEmpty()) {
            throw new DSSExternalResourceException("Cannot process the recuperation of data from url. List of URLs is empty!");
        }

        final Map<String, Throwable> exceptions = new HashMap<>(); // store map of exception thrown for urls
        for (String urlString : urlStrings) {
            LOG.debug("Processing a retrieve of data with URL [{}]...", urlString);
            try {
                final byte[] bytes = get(urlString);
                if (bytes == null || bytes.length == 0) {
                    LOG.debug("The retrieved content from URL [{}] is empty. Continue with other URLs...", urlString);
                    continue;
                }
                return new DataAndUrl(urlString, bytes);
            } catch (Exception e) {
                LOG.warn("Cannot obtain data using '{}' : {}", urlString, e.getMessage());
                exceptions.put(urlString, e);
            }
        }
        throw new DSSDataLoaderMultipleException(exceptions);

    }

    TriFunction<List<String>, String, Integer, Boolean> checkType = (param, type, size) -> param != null && param.size() == size && param.get(size - 1).endsWith(type);


    public DataAndUrl certificationGet(String urlString) {
        List<String> urlParams = getPathParams(urlString);
//
//        if (isGetCertificate(urlParams)) {
//            try {
//                return new DataAndUrl(urlString, certService.getCertificate(getCleanId(urlParams, 1, ".crt")).getEncoded());
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        } else if (isGetCertPem(urlParams)) {
//            return new DataAndUrl(urlString, certService.getPemCertificate(getCleanId(urlParams, 1, ".pem")));
//        } else if (isGetPrivateKey(urlParams)) {
//            return new DataAndUrl(urlString, certService.getPrivateKey(getCleanId(urlParams, 1, ".key")).getEncoded());
//        } else if (isGetCertBySerialNumAndIssuer(urlParams)) {
//            return new DataAndUrl(urlString, certService.getBySerialNumberAndParent(Long.parseLong(getCleanId(urlParams, 2, ".crt")), urlParams.get(1)).getCertificateToken());
//        }
        throw new Error500Exception("Bad url");
    }

    public DataAndUrl ocspPost(String urlString, byte[] content) {
        List<String> urlParams = getPathParams(urlString);
//
//        final ByteArrayInputStream inputStream = new ByteArrayInputStream(content);
//        if (isOcsp(urlParams)) {
//            String certificateId = urlParams.get(1);
//            return new DataAndUrl(urlString, ocspGenerator.getOCSPResponse(certService.getCertificateEntity(certificateId), inputStream));
//        } else if (isOcspForReqAlgo(urlParams)) {
//            String certificateId = urlParams.get(3);
//            String idCa = urlParams.get(2);
//            DBCertEntity dbCertEntity = urlParams.contains("reqAlgo") ? certService.getCertificateEntity(certificateId) : certService.getBySerialNumberAndParent(Long.parseLong(certificateId), idCa);
//            return new DataAndUrl(urlString, ocspGenerator.getOCSPWithRequestAlgo(dbCertEntity, inputStream));
//        } else if (isOcspForDateRange(urlParams)) {
//            Date endDate = parseToDate(urlParams.get(2));
//            Date startDate = parseToDate(urlParams.get(1));
//            String certificateId = urlParams.get(4);
//            RevocationReason revocationReason = RevocationReason.valueOf(urlParams.get(3));
//            return new DataAndUrl(urlString, ocspGenerator.getCustomOCSPResponse(certService.getCertificateEntity(certificateId), startDate, endDate, revocationReason, inputStream));
//        } else if (isOcspForDate(urlParams)) {
//            if (urlParams.contains("fail")) new DataAndUrl(urlString, ocspGenerator.getFailedOCSPResponse());
//            return new DataAndUrl(urlString, ocspGenerator.getCustomOCSPResponse(certService.getCertificateEntity(urlParams.get(2)), parseToDate(urlParams.get(1)), inputStream));
//
//        } else if (isGetError500(urlParams)) throw new Error500Exception("Something wrong happened");
        throw new Error500Exception("Bad url");
    }


    public DataAndUrl crlGet(String urlString) {
        List<String> urlParams = getPathParams(urlString);

        if (isGetCrl(urlParams)) {
            return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getCertificateEntity(getCleanId(urlParams, 1, ".crt"))));
        } else if (isGetUrlWithSeralNumberAndIssuer(urlParams)) {
            if (urlParams.contains("pem")) {
                return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getCertificateEntity(getCleanId(urlParams, 2, ".crl")), parseToDate(urlParams.get(1)), false));
            }
            if (urlParams.contains("error-500")) {
                errorGenerator.getError500();
            }
            return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getCertificateEntity(getCleanId(urlParams, 3, ".crl")), parseToDate(urlParams.get(1)), false));
        } else if (isGetCrlForDate(urlParams)) {
            return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getCertificateEntity(getCleanId(urlParams, 4, ".crl")), parseToDate(urlParams.get(2)), parseToDate(urlParams.get(3))));
        } else if (getCrlExtended(urlParams)) {
            if (urlParams.contains("extended")) {
                return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getBySerialNumberAndParent(Long.parseLong(urlParams.get(4)), urlParams.get(3))));
            }
            return new DataAndUrl(urlString, crlGenerator.getCRL(certService.getCertificateEntity(getCleanId(urlParams, 4, ".crl")), parseToDate(urlParams.get(2)), parseToDate(urlParams.get(3))));
        }
        throw new Error500Exception("Bad url");
    }


    public DataAndUrl keyStoreGet(String urlString) {
        List<String> urlParams = getPathParams(urlString);
        if (isGetKeystoreForCert(urlParams)) {
            return new DataAndUrl(urlString, keystoreGenerator.getKeystore(getCleanId(urlParams, 1, ".p12")));
        } else if (isGetRoots(urlParams)) {
            return new DataAndUrl(urlString, keystoreGenerator.getRoots());
        } else if (isGetTrustAnchors(urlParams)) {
            return new DataAndUrl(urlString, keystoreGenerator.getTrustAnchors());
        } else if (isGetToBeIgnored(urlParams)) {
            return new DataAndUrl(urlString, keystoreGenerator.getToBeIgnored());
        } else if (isGetTrustAnchorsForPKI(urlParams)) {
            return new DataAndUrl(urlString, keystoreGenerator.getTrustAnchorsForPKI(getCleanId(urlParams, 1, ".jks")));
        }
        throw new Error500Exception("Bad url");
    }


    public DataAndUrl tsaPost(String urlString, byte[] content) {
        List<String> urlParams = getPathParams(urlString);

        final ByteArrayInputStream inputStream = new ByteArrayInputStream(content);

        if (isTimesTamp(urlParams)) {
            return new DataAndUrl(urlString, timestampGenerator.getTimestamp(urlParams.get(1), new Date(), inputStream));
        } else if (isTimestampForDate(urlParams)) {
            return new DataAndUrl(urlString, timestampGenerator.getTimestamp(urlParams.get(2), parseToDate(urlParams.get(1)), inputStream));
        } else if (isGetError500(urlParams)) {
            throw new Error500Exception("Something wrong happened");
        } else if (isFailTimestamp(urlParams)) {
            return new DataAndUrl(urlString, timestampGenerator.getFailedTimestamp(urlParams.get(2), inputStream));
        }
        throw new Error500Exception("Bad url");
    }

    // Helper method for parsing a date from a string with the "yyyy-MM-dd-HH-mm" format.
    private Date parseToDate(String string) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd-HH-mm").parse(string);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private List<String> getPathParams(String urlString) {
        String[] pathSegments = new String[100];
        try {
            URI uri = new URI(urlString);
            String path = uri.getPath(); // Get the path part of the URL

            if (path != null) {
                pathSegments = path.split("/"); // Split the path into individual segments
            } else {
                LOG.error("No path found in the URL.");
            }
        } catch (URISyntaxException e) {
            LOG.error(e.getMessage());
        }

        List<String> urlParams = new ArrayList<>(Arrays.asList(pathSegments));
        urlParams.remove("");// delete URL
        urlParams.remove("pki-factory");//delete context-path
        if (urlParams.size() == 0) {
            throw new Error500Exception("Bad url");
        }
        return urlParams;
    }

    public byte[] get(String s, boolean b) {
        return new byte[0];
    }

    @Override
    public byte[] post(String url, byte[] content) {
        LOG.debug("Fetching data via POST from url {}", url);
        return PkiDataLoaderType.getType(url).getTriFunction().apply(this, url, content);
    }

    @Override
    public void setContentType(String s) {

    }

    private static String getCleanId(List<String> urlParams, int index, String target) {
        return urlParams.get(index).replace(target, "");
    }

    private boolean isFailTimestamp(List<String> urlParams) {
        return checkType.apply(urlParams, "", 3) && urlParams.contains("fail");
    }

    private boolean isGetError500(List<String> urlParams) {
        return checkType.apply(urlParams, "", 3) && urlParams.contains("error-500");
    }

    private Boolean isTimestampForDate(List<String> urlParams) {
        return checkType.apply(urlParams, "", 3) && !urlParams.contains("fail") && !urlParams.contains("error-500");
    }

    private Boolean isTimesTamp(List<String> urlParams) {
        return checkType.apply(urlParams, "", 2);
    }


    private Boolean isOcsp(List<String> urlParams) {
        return checkType.apply(urlParams, "", 2);
    }

    private Boolean isOcspForReqAlgo(List<String> urlParams) {
        return checkType.apply(urlParams, "", 4);
    }

    private Boolean isOcspForDateRange(List<String> urlParams) {
        return checkType.apply(urlParams, "", 5);
    }

    private Boolean isOcspForDate(List<String> urlParams) {
        return checkType.apply(urlParams, "", 3);
    }

    private Boolean isGetCertBySerialNumAndIssuer(List<String> urlParams) {
        return checkType.apply(urlParams, "", 3);
    }

    private Boolean isGetPrivateKey(List<String> urlParams) {
        return checkType.apply(urlParams, ".key", 2);
    }

    private Boolean isGetCertPem(List<String> urlParams) {
        return checkType.apply(urlParams, ".pem", 2);
    }

    private Boolean isGetCertificate(List<String> urlParams) {
        return checkType.apply(urlParams, ".crt", 2);
    }

    private Boolean getCrlExtended(List<String> urlParams) {
        return checkType.apply(urlParams, ".crl", 4);
    }

    private Boolean isGetCrlForDate(List<String> urlParams) {
        return checkType.apply(urlParams, ".crl", 5);
    }

    private Boolean isGetUrlWithSeralNumberAndIssuer(List<String> urlParams) {
        return checkType.apply(urlParams, ".crl", 3);
    }

    private Boolean isGetCrl(List<String> urlParams) {
        return checkType.apply(urlParams, ".crl", 2);
    }

    private Boolean isGetTrustAnchorsForPKI(List<String> urlParams) {
        return checkType.apply(urlParams, ".jks", 2);
    }

    private Boolean isGetToBeIgnored(List<String> urlParams) {
        return checkType.apply(urlParams, "to-be-ignored.jks", 2);
    }

    private Boolean isGetTrustAnchors(List<String> urlParams) {
        return checkType.apply(urlParams, "trust-anchors.jks", 2);
    }

    private Boolean isGetRoots(List<String> urlParams) {
        return checkType.apply(urlParams, "roots.jks", 2);
    }

    private Boolean isGetKeystoreForCert(List<String> urlParams) {
        return checkType.apply(urlParams, ".p12", 2);
    }

}
