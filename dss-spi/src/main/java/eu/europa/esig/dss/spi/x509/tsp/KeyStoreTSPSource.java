package eu.europa.esig.dss.spi.x509.tsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * TSPSource implementation allowing to configure issuance of a time-stamp using a local {@code KeyStore}
 *
 */
public class KeyStoreTSPSource implements TSPSource {

    private static final long serialVersionUID = -5082887845359355029L;

    /** SecureRandom used to calculate a serial number for a timestamp */
    private final SecureRandom secureRandom = new SecureRandom();

    /** The KeyStore to be used to access the key to create a timestamp */
    private KeyStore keyStore;

    /** The alias of the key entry to be used to sign the timestamp */
    private String alias;

    /** The password protection to access the key entry within the key store */
    private char[] keyEntryPassword;

    /** Collection of digest algorithms accepted by the current TSP source in the request */
    private Collection<DigestAlgorithm> acceptedDigestAlgorithms = Arrays.asList(
            DigestAlgorithm.SHA224, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512);

    /** The TSA policy */
    private String tsaPolicy = "1.2.3.4";

    /** The static production date of the timestamp */
    private Date productionTime;

    /** The Digest Algorithm of the signature of the created time-stamp token */
    private DigestAlgorithm tstDigestAlgorithm = DigestAlgorithm.SHA256;

    /** Defines whether a time-stamp should be generated with a hash algorithm using a Probabilistic Signature Scheme (always MGF1 is used) */
    private boolean enablePSS = false;

    /**
     * Default constructor instantiating empty configuration of the KeyStoreTSPSource
     */
    public KeyStoreTSPSource() {
        // empty
    }

    /**
     * Constructor instantiating the key store content and key entry data
     *
     * @param ksContent byte array representing the key store content
     * @param ksType {@link String} representing the type of the key store
     * @param ksPassword char array representing a password from the key store
     * @param alias {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyStoreTSPSource(byte[] ksContent, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) {
        this(loadKeyStore(new ByteArrayInputStream(ksContent), ksType, ksPassword), alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store path location and key entry data
     *
     * @param ksPath {@link String} representing the path to the key store
     * @param ksType {@link String} representing the type of the key store
     * @param ksPassword char array representing a password from the key store
     * @param alias {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     * @throws IOException if not able to load the key store file
     */
    public KeyStoreTSPSource(String ksPath, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) throws IOException {
        this(new File(ksPath), ksType, ksPassword, alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store File and key entry data
     *
     * @param ksFile {@link File} key store file
     * @param ksType {@link String} representing the type of the key store
     * @param ksPassword char array representing a password from the key store
     * @param alias {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     * @throws IOException if not able to load the key store file
     */
    public KeyStoreTSPSource(File ksFile, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) throws IOException {
        this(Files.newInputStream(ksFile.toPath()), ksType, ksPassword, alias, keyEntryPassword);
    }

    /**
     * Constructor instantiating the key store InputStream and key entry data
     *
     * @param ksIs {@link InputStream} representing the key store content
     * @param ksType {@link String} representing the type of the key store
     * @param ksPassword char array representing a password from the key store
     * @param alias {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyStoreTSPSource(InputStream ksIs, String ksType, char[] ksPassword, String alias, char[] keyEntryPassword) {
        this(loadKeyStore(ksIs, ksType, ksPassword), alias, keyEntryPassword);
    }

    private static KeyStore loadKeyStore(InputStream keyStoreIs, String ksType, char[] keyStorePassword) {
        try (InputStream is = keyStoreIs) {
            KeyStore keyStore = KeyStore.getInstance(ksType);
            keyStore.load(is, keyStorePassword);
            return keyStore;
        } catch (Exception e) {
            throw new DSSException("Unable to instantiate KeyStore", e);
        }
    }

    /**
     * Constructor instantiating the key store and key entry data
     *
     * @param keyStore {@link KeyStore}
     * @param alias {@link String} alias of the key entry to be used for timestamp signing
     * @param keyEntryPassword char array representing a password from the key entry
     */
    public KeyStoreTSPSource(KeyStore keyStore, String alias, char[] keyEntryPassword) {
        this.keyStore = keyStore;
        this.alias = alias;
        this.keyEntryPassword = keyEntryPassword;
    }

    /**
     * Sets the KeyStore (required)
     *
     * @param keyStore {@link KeyStore}
     */
    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Sets the alias of the key entry within the KeyStore to be used to create a timestamp (required)
     *
     * @param alias {@link String}
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * Sets the password protection String to access the key entry under the defined alias
     *
     * @param keyEntryPassword char array
     */
    public void setKeyEntryPassword(char[] keyEntryPassword) {
        this.keyEntryPassword = keyEntryPassword;
    }

    /**
     * Sets the TSA policy
     * NOTE: if not defined, a dummy "1.2.3.4" policy OID will be used
     *
     * @param tsaPolicy {@link String}
     */
    public void setTsaPolicy(String tsaPolicy) {
        this.tsaPolicy = tsaPolicy;
    }

    /**
     * Sets a collection of digest algorithms to be accepted within timestamp request
     * Default: SHA-224, SHA-256, SHA-384, SHA-512
     *
     * @param digestAlgorithms a collection of {@link DigestAlgorithm}s
     */
    public void setAcceptedDigestAlgorithms(Collection<DigestAlgorithm> digestAlgorithms) {
        this.acceptedDigestAlgorithms = digestAlgorithms;
    }

    /**
     * Sets a production time of the timestamp.
     * NOTE: if not defined, the current time will be used.
     *
     * @param productionTime {@link Date}
     */
    public void setProductionTime(Date productionTime) {
        this.productionTime = productionTime;
    }

    /**
     * Sets the digest algorithm of the signature of the generated time-stamp token
     * Default: DigestAlgorithm.SHA256
     *
     * @param tstDigestAlgorithm {@link DigestAlgorithm}
     */
    public void setTstDigestAlgorithm(DigestAlgorithm tstDigestAlgorithm) {
        this.tstDigestAlgorithm = tstDigestAlgorithm;
    }

    /**
     * Sets whether a time-stamp should be generated with a hash algorithm using the Probabilistic Signature Scheme (MGF1 is used)
     * Default: FALSE (MGF1 is not applied)
     *
     * @param enablePSS whether MGF1 shall be applied
     */
    public void setEnablePSS(boolean enablePSS) {
        this.enablePSS = enablePSS;
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        Objects.requireNonNull(keyStore, "KeyStore is not defined!");
        Objects.requireNonNull(alias, "Alias is not defined!");
        Objects.requireNonNull(keyEntryPassword, "Password from key entry is not defined!");
        Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm is not defined!");
        Objects.requireNonNull(digest, "digest is not defined!");
        if (!acceptedDigestAlgorithms.contains(digestAlgorithm)) {
            throw new DSSException(String.format(
                    "DigestAlgorithm '%s' is not supported by the KeyStoreTSPSource implementation!", digestAlgorithm));
        }

        try {
            if (!keyStore.isKeyEntry(alias)) {
                throw new IllegalArgumentException(String.format(
                        "No related/supported key entry found for alias '%s'!", alias));
            }
            if (!keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                throw new IllegalArgumentException(String.format(
                        "No key entry found for alias '%s' is not instance of a PrivateKeyEntry!", alias));
            }

            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) keyStore
                    .getEntry(alias, new KeyStore.PasswordProtection(keyEntryPassword));
            ASN1ObjectIdentifier digestAlgoOID = getASN1ObjectIdentifier(digestAlgorithm);

            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.setCertReq(true);
            TimeStampRequest request = requestGenerator.generate(digestAlgoOID, digest);

            EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.forKey(keyEntry.getPrivateKey());
            String sigAlgoName = getSignatureAlgorithmName(tstDigestAlgorithm, encryptionAlgorithm, enablePSS);

            ContentSigner signer = new JcaContentSignerBuilder(sigAlgoName).build(keyEntry.getPrivateKey());

            X509Certificate x509Certificate = (X509Certificate) keyEntry.getCertificate();
            X509CertificateHolder certificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
            SignerInfoGenerator infoGenerator = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
                    .build(signer, certificateHolder);

            AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(digestAlgoOID);
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

            TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(
                    infoGenerator, digestCalculator, getASN1ObjectIdentifier(tsaPolicy));

            X509Certificate[] certificateChain = (X509Certificate[]) keyEntry.getCertificateChain();
            tokenGenerator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

            TimeStampResponseGenerator responseGenerator = new TimeStampResponseGenerator(
                    tokenGenerator, getAcceptedDigestAlgorithmIdentifiers());

            Date date = productionTime != null ? productionTime : new Date();
            TimeStampResponse response = generateResponse(responseGenerator, request, date);
            return new TimestampBinary(response.getTimeStampToken().getEncoded());

        } catch (UnrecoverableEntryException e) {
            throw new DSSException(String.format("Unable to recover the key entry with alias '%s'. Reason : %s", alias, e.getMessage()), e);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateEncodingException | IOException |
                 OperatorCreationException | TSPException e) {
            throw new DSSException(String.format("Unable to generate a timestamp. Reason : %s", e.getMessage()), e);
        }
    }

    private Set<ASN1ObjectIdentifier> getAcceptedDigestAlgorithmIdentifiers() {
        Set<ASN1ObjectIdentifier> result = new HashSet<>();
        for (DigestAlgorithm digestAlgorithm : acceptedDigestAlgorithms) {
            result.add(getASN1ObjectIdentifier(digestAlgorithm));
        }
        return result;
    }

    private ASN1ObjectIdentifier getASN1ObjectIdentifier(EncryptionAlgorithm encryptionAlgorithm) {
        return getASN1ObjectIdentifier(encryptionAlgorithm.getOid());
    }

    private ASN1ObjectIdentifier getASN1ObjectIdentifier(DigestAlgorithm digestAlgorithm) {
        return getASN1ObjectIdentifier(digestAlgorithm.getOid());
    }


    private ASN1ObjectIdentifier getASN1ObjectIdentifier(String oid) {
        return new ASN1ObjectIdentifier(oid);
    }

    /**
     * Returns the target signature algorithm to be used to time-stamp generation
     *
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @param encryptionAlgorithm {@link EncryptionAlgorithm}
     * @param enablePSS whether the MGF1 shall be applied
     * @return {@link String} signature algorithm name
     */
    protected String getSignatureAlgorithmName(DigestAlgorithm digestAlgorithm, EncryptionAlgorithm encryptionAlgorithm, boolean enablePSS) {
        AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(getASN1ObjectIdentifier(digestAlgorithm));
        AlgorithmIdentifier encryptionAlg = new AlgorithmIdentifier(getASN1ObjectIdentifier(encryptionAlgorithm));

        DefaultCMSSignatureAlgorithmNameGenerator sigAlgoGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        String sigAlgoName = sigAlgoGenerator.getSignatureName(digestAlgorithmIdentifier, encryptionAlg);
        if (enablePSS) {
            sigAlgoName += "andMGF1";
        }
        return sigAlgoName;
    }

    /**
     * This method generates a timestamp response
     *
     * @param responseGenerator {@link TimeStampResponseGenerator}
     * @param request {@link TimeStampRequest}
     * @param date {@link Date} production time of the timestamp
     * @return {@link TimeStampResponse}
     * @throws TSPException if an error occurs during the timestamp response generation
     */
    protected TimeStampResponse generateResponse(TimeStampResponseGenerator responseGenerator, TimeStampRequest request, Date date) throws TSPException {
        return responseGenerator.generate(request, getTimeStampSerialNumber(), date);
    }

    /**
     * Generates a serial number of the produced timestamp token
     *
     * @return {@link BigInteger} serial number
     */
    protected BigInteger getTimeStampSerialNumber() {
        return new BigInteger(128, secureRandom);
    }

}
