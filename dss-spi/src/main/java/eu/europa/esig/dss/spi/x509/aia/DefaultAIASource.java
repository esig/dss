package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The class is used to download issuer certificates by AIA from remote sources
 *
 */
public class DefaultAIASource implements OnlineAIASource {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAIASource.class);

    /**
     * The used {@code DataLoader} to download data
     */
    private DataLoader dataLoader;

    /**
     * Collection of protocols to be accepted and used by the source
     *
     * Default: all protocols are accepted (FILE, HTTP, HTTPS, LDAP, FTP).
     */
    private Collection<Protocol> acceptedProtocols = Arrays.asList(Protocol.values());

    /**
     * Empty constructor.
     * Instantiates a {@code NativeHTTPDataLoader} as a default data loader
     */
    public DefaultAIASource() {
        this(new NativeHTTPDataLoader());
    }

    /**
     * Default constructor with a defined {@code DataLoader}
     *
     * @param dataLoader {@link DataLoader} to be used
     */
    public DefaultAIASource(DataLoader dataLoader) {
        Objects.requireNonNull(dataLoader, "dataLoader cannot be null!");
        this.dataLoader = dataLoader;
    }

    @Override
    public void setDataLoader(DataLoader dataLoader) {
        Objects.requireNonNull(dataLoader, "dataLoader cannot be null!");
        this.dataLoader = dataLoader;
    }

    /**
     * Defines a set of protocols to be accepted and used by the AIA Source.
     * All protocols which are not defined in the collection will be skipped.
     *
     * Default: all protocols are accepted (FILE, HTTP, HTTPS, LDAP, FTP).
     *
     * @param acceptedProtocols a collection of accepted {@link Protocol}s
     */
    public void setAcceptedProtocols(Collection<Protocol> acceptedProtocols) {
        this.acceptedProtocols = acceptedProtocols;
    }

    @Override
    public Set<CertificateToken> getCertificatesByAIA(final CertificateToken certificateToken) {
        List<CertificatesAndAIAUrl> certificatesAndAIAUrls = getCertificatesAndAIAUrls(certificateToken);
        if (Utils.isCollectionNotEmpty(certificatesAndAIAUrls)) {
            final Set<CertificateToken> allCertificates = new LinkedHashSet<>();
            for (CertificatesAndAIAUrl certificatesByAiaUrl : certificatesAndAIAUrls) {
                final List<CertificateToken> certificates = certificatesByAiaUrl.getCertificates();
                if (Utils.isCollectionNotEmpty(certificates)) {
                    allCertificates.addAll(certificates);
                }
            }
            return allCertificates;
        }
        return Collections.emptySet();
    }
    
    @Override
    public List<CertificatesAndAIAUrl> getCertificatesAndAIAUrls(CertificateToken certificateToken) {
        List<String> urls = DSSASN1Utils.getCAAccessLocations(certificateToken);

        if (Utils.isCollectionEmpty(urls)) {
            LOG.info("There is no AIA extension for certificate download.");
            return Collections.emptyList();
        }
        if (dataLoader == null) {
            LOG.warn("There is no DataLoader defined to load Certificates from AIA extension (urls : {})", urls);
            return Collections.emptyList();
        }

        final List<CertificatesAndAIAUrl> certificatesAndAIAUrls = new ArrayList<>();

        for (String url : urls) {
            if (!isUrlAccepted(url)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The url '{}' is not accepted by the defined collection of Protocols. " +
                            "The entry is skipped.", url);
                }
                continue;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Loading certificate(s) from '{}'.", url);
            }

            byte[] bytes;
            try {
                bytes = dataLoader.get(url);

            } catch (Exception e) {
                String errorMessage = "Unable to download certificate from '{}': {}";
                if (LOG.isDebugEnabled()) {
                    LOG.warn(errorMessage, url, e.getMessage(), e);
                } else {
                    LOG.warn(errorMessage, url, e.getMessage());
                }
                continue;
            }

            List<CertificateToken> loadedCertificates = Collections.emptyList();

            if (Utils.isArrayNotEmpty(bytes)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Base64 content : {}", Utils.toBase64(bytes));
                }
                try (InputStream is = new ByteArrayInputStream(bytes)) {
                    loadedCertificates = DSSUtils.loadCertificateFromP7c(is);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{} certificate(s) loaded from '{}'", loadedCertificates.size(), url);
                    }

                } catch (Exception e) {
                    String errorMessage = "Unable to parse certificate(s) from AIA (url: {}) : {}";
                    if (LOG.isDebugEnabled()) {
                        LOG.warn(errorMessage, url, e.getMessage(), e);
                    } else {
                        LOG.warn(errorMessage, url, e.getMessage());
                    }
                }

            } else {
                LOG.warn("Empty content from {}.", url);
            }

            certificatesAndAIAUrls.add(new CertificatesAndAIAUrl(url, loadedCertificates));
        }

        return certificatesAndAIAUrls;
    }

    private boolean isUrlAccepted(String url) {
        if (Utils.isCollectionNotEmpty(acceptedProtocols)) {
            for (Protocol protocol : acceptedProtocols) {
                if (protocol.isTheSame(url)) {
                    return true;
                }
            }
        }
        return false;
    }

}
