/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNotApplicableMethodException;
import eu.europa.ec.markt.dss.exception.DSSNotETSICompliantException;
import eu.europa.ec.markt.dss.exception.DSSNullReturnedException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.validation.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonTrustedCertificateSource;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

/**
 * This class allows to extract all the trust anchors defined by the trusted lists. The LOTL is used as the entry point of the process.
 *
 * @version $Revision: 1845 $ - $Date: 2013-04-04 17:46:25 +0200 (Thu, 04 Apr 2013) $
 */

public class TrustedListsCertificateSource extends CommonTrustedCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(TrustedListsCertificateSource.class);

	// prefix of a resource to be found on the classpath - Spring notation
	private static final String CP = "classpath://";
	private static final String FILE = "file://";

	public static final String TSL_HASH_PROPERTIES = "tsl_hash.properties";
	public static final String TSL_NEXT_UPDATE_PROPERTIES = "tsl_next_update.properties";

	private File tslPropertyCacheFolder = new File(System.getProperty("java.io.tmpdir"));
	private Properties tslHashes = null;
	private Properties tslNextUpdates = null;

	protected TSLRefreshPolicy tslRefreshPolicy = TSLRefreshPolicy.ALWAYS;

	private CommonsDataLoader commonsDataLoader = new CommonsDataLoader();

	protected String lotlUrl;

	protected transient DataLoader dataLoader;

	private Map<String, String> diagnosticInfo = new HashMap<String, String>();

	/**
	 * Defines if the TL signature must be checked. The default value is true.
	 */
	protected boolean checkSignature = true;

	protected String lotlCertificate;

	static {

		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * The default constructor.
	 */
	public TrustedListsCertificateSource() {
		super();
	}

	/**
	 * The copy constructor.
	 *
	 * @param trustedListsCertificateSource
	 */
	public TrustedListsCertificateSource(final TrustedListsCertificateSource trustedListsCertificateSource) {

		this.setDataLoader(trustedListsCertificateSource.dataLoader);
		this.setCheckSignature(trustedListsCertificateSource.checkSignature);
		this.setLotlCertificate(trustedListsCertificateSource.lotlCertificate);
		this.setLotlUrl(trustedListsCertificateSource.lotlUrl);
		this.setTslPropertyCacheFolder(trustedListsCertificateSource.tslPropertyCacheFolder);
		this.setTslRefreshPolicy(trustedListsCertificateSource.tslRefreshPolicy);
	}

	@Override
	protected CertificateSourceType getCertificateSourceType() {

		return CertificateSourceType.TRUSTED_LIST;
	}

	/**
	 * This method is not applicable for this kind of certificate source. You should use {@link
	 * #addCertificate(java.security.cert.X509Certificate, eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo)}
	 *
	 * @param x509Certificate the certificate you have to trust
	 * @return the corresponding certificate token
	 */
	@Override
	public CertificateToken addCertificate(final X509Certificate x509Certificate) {

		throw new DSSNotApplicableMethodException(getClass());
	}

	/**
	 * Adds a service entry (current or history) to the list of certificate tokens.
	 *
	 * @param x509Certificate the certificate which identifies the trusted service
	 * @param trustedService  Object defining the trusted service
	 * @param tsProvider      Object defining the trusted service provider, must be the parent of the trusted service
	 * @param tlWellSigned    Indicates if the signature of trusted list is valid
	 */
	private synchronized void addCertificate(final X509Certificate x509Certificate, final AbstractTrustService trustedService, final TrustServiceProvider tsProvider,
	                                         final boolean tlWellSigned) {

		try {
			final ServiceInfo serviceInfo = getServiceInfo(trustedService, tsProvider, tlWellSigned);
			addCertificate(x509Certificate, serviceInfo);
		} catch (DSSNotETSICompliantException ex) {

			LOG.error("The entry for " + trustedService.getServiceName() + " doesn't respect ETSI specification " + ex.getLocalizedMessage());
		}
	}

	/**
	 * This method return the service info object enclosing the certificate.
	 *
	 * @param trustedService Object defining the trusted service
	 * @param tsProvider     Object defining the trusted service provider, must be the parent of the trusted service
	 * @param tlWellSigned   Indicates if the signature of trusted list is valid
	 * @return
	 */
	private ServiceInfo getServiceInfo(final AbstractTrustService trustedService, final TrustServiceProvider tsProvider, final boolean tlWellSigned) {

		// System.out.println("--- > ServiceName: " + trustedService.getServiceName());
		final ServiceInfo serviceInfo = trustedService.createServiceInfo();

		serviceInfo.setServiceName(trustedService.getServiceName());
		serviceInfo.setStatus(trustedService.getStatus());
		serviceInfo.setStatusStartDate(trustedService.getStatusStartDate());
		serviceInfo.setStatusEndDate(trustedService.getStatusEndDate());
		serviceInfo.setType(trustedService.getType());

		serviceInfo.setTspElectronicAddress(tsProvider.getElectronicAddress());
		serviceInfo.setTspName(tsProvider.getName());
		serviceInfo.setTspPostalAddress(tsProvider.getPostalAddress());
		serviceInfo.setTspTradeName(tsProvider.getTradeName());

		serviceInfo.setTlWellSigned(tlWellSigned);

		return serviceInfo;
	}

	/**
	 * This method returns the diagnostic data concerning the certificates retrieval process from the trusted lists. It can be used for
	 * debugging purposes.
	 *
	 * @return the diagnosticInfo
	 */
	public Map<String, String> getDiagnosticInfo() {

		return Collections.unmodifiableMap(diagnosticInfo);
	}

	/**
	 * Gets the LOTL certificate as an inputStream stream
	 *
	 * @return the inputStream stream
	 * @throws DSSException
	 */
	private InputStream getLotlCertificateInputStream() throws DSSException {

		InputStream inputStream = null;
		try {

			if (lotlCertificate.toLowerCase().startsWith(CP)) {

				final String lotlCertificate_ = lotlCertificate.substring(CP.length() - 1);
				inputStream = getClass().getResourceAsStream(lotlCertificate_);
			} else if (lotlCertificate.toLowerCase().startsWith(FILE)) {

				final URL url = new File(lotlCertificate.substring(FILE.length())).toURI().toURL();
				inputStream = url.openStream();
			} else {

				final URL url = new URL(lotlCertificate);
				inputStream = url.openStream();
			}
			return inputStream;
		} catch (Exception e) {

			DSSUtils.closeQuietly(inputStream);
			throw new DSSException(e);
		}
	}

	/**
	 * Load a trusted list form the specified URL. If the {@code signingCertList} contains any {@code X509Certificate} then the validation of the signature of the TSL is done.
	 *
	 * @param url             of the TSL to load
	 * @param signingCertList the {@code List} of the possible signing certificates
	 * @return {@code TrustStatusList}
	 */
	private TrustStatusList getTrustStatusList(final String url, final List<X509Certificate> signingCertList) {

		boolean refresh = shouldRefresh(url);
		final byte[] bytes = dataLoader.get(url, refresh);
		if (bytes == null) {
			throw new DSSNullReturnedException(url);
		}
		boolean coreValidity = checkSignature ? validateTslSignature(signingCertList, bytes) : true;
		final Document doc = DSSXMLUtils.buildDOM(bytes);
		final TrustStatusList trustStatusList = TrustServiceListFactory.newInstance(doc);
		trustStatusList.setWellSigned(coreValidity);
		updateTslNextUpdateDate(url, trustStatusList);
		return trustStatusList;
	}

	private boolean validateTslSignature(final List<X509Certificate> signingCertList, final byte[] bytes) {

		boolean coreValidity = false;
		if (signingCertList != null) {

			final XMLDocumentValidator xmlDocumentValidator = prepareSignatureValidation(signingCertList, bytes);
			final List<AdvancedSignature> signatures = xmlDocumentValidator.getSignatures();
			if (signatures.size() == 0) {
				throw new DSSException("Not ETSI compliant signature. The Xml is not signed.");
			}
			final Reports reports = xmlDocumentValidator.validateDocument();
			final SimpleReport simpleReport = reports.getSimpleReport();
			final List<String> signatureIdList = simpleReport.getSignatureIdList();
			final String signatureId = signatureIdList.get(0);
			final String indication = simpleReport.getIndication(signatureId);
			coreValidity = Indication.VALID.equals(indication);
			LOG.info("The TSL signature validity: " + coreValidity);
			if (!coreValidity) {

				LOG.info("The TSL signature validity details:\n" + simpleReport);
				throw new DSSException("Not ETSI compliant signature. The signature is not valid.");
			}
		}
		return coreValidity;
	}

	protected void updateTSLHashCode(final String url, final String currentHashValue) {

		ensureTSLHashCodePropertyFileLoaded();
		tslHashes.setProperty(url, currentHashValue);
		saveProperties(tslHashes, TSL_HASH_PROPERTIES);
	}

	protected String getTSLHashCode(final String url) {

		ensureTSLHashCodePropertyFileLoaded();
		return tslHashes.getProperty(url);
	}

	private void ensureTSLHashCodePropertyFileLoaded() {
		if (tslHashes == null) {
			tslHashes = loadProperties(TSL_HASH_PROPERTIES);
		}
	}

	protected String getTSLNextUpdateDate(final String url) {

		ensureTSLNextUpdatePropertyFileLoaded();
		return tslNextUpdates.getProperty(url);
	}

	protected void updateTslNextUpdateDate(final String url, final TrustStatusList tsl) {

		ensureTSLNextUpdatePropertyFileLoaded();
		final Date nextUpdate = tsl.getNextUpdate();
		tslNextUpdates.setProperty(url, DSSUtils.formatInternal(nextUpdate));
		saveProperties(tslNextUpdates, TSL_NEXT_UPDATE_PROPERTIES);
	}

	private void ensureTSLNextUpdatePropertyFileLoaded() {
		if (tslNextUpdates == null) {
			tslNextUpdates = loadProperties(TSL_NEXT_UPDATE_PROPERTIES);
		}
	}

	private boolean shouldRefresh(final String url) {

		if (tslRefreshPolicy == TSLRefreshPolicy.ALWAYS) {
			return true;
		}
		if (tslRefreshPolicy == TSLRefreshPolicy.NEVER) {
			return false;
		}
		// ETSI TS 119 612 V1.1.1 (2013-06)
		// 6.1 TL publication
		final String urlSha2 = url.substring(0, url.lastIndexOf(".")) + ".sha2";
		boolean refresh = false;
		try {
			final byte[] sha2Bytes = commonsDataLoader.get(urlSha2);
			final String currentHashValue = new String(sha2Bytes).trim();
			if (DSSUtils.isBlank(currentHashValue)) {
				throw new DSSException("SHA256 does not exist!");
			}
			final String hashValue = getTSLHashCode(url);
			refresh = hashValue == null || !currentHashValue.equals(hashValue);
			if (refresh) {

				updateTSLHashCode(url, currentHashValue);
			}
		} catch (Exception e) {
			if (tslRefreshPolicy == TSLRefreshPolicy.WHEN_NECESSARY_OR_INDETERMINATE) {
				return true;
			}
		}
		// if the current date is after the last known nextUpdate then the refresh is forced.
		final String tslNextUpdateProperty = getTSLNextUpdateDate(url);
		final Date tslNextUpdateDate = DSSUtils.quietlyParseDate(tslNextUpdateProperty);
		if (tslNextUpdateDate != null && new Date().after(tslNextUpdateDate)) {
			refresh = true;
		}
		return refresh;
	}

	private XMLDocumentValidator prepareSignatureValidation(final List<X509Certificate> signingCertList, final byte[] bytes) {

		final CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		for (final X509Certificate x509Certificate : signingCertList) {

			commonTrustedCertificateSource.addCertificate(x509Certificate);
		}
		final CertificateVerifier certificateVerifier = new CommonCertificateVerifier(true);
		certificateVerifier.setTrustedCertSource(commonTrustedCertificateSource);

		final DSSDocument dssDocument = new InMemoryDocument(bytes);
		final XMLDocumentValidator xmlDocumentValidator = new XMLDocumentValidator(dssDocument);
		xmlDocumentValidator.setCertificateVerifier(certificateVerifier);
		// To increase the security: the default {@code XPathQueryHolder} is used.
		final List<XPathQueryHolder> xPathQueryHolders = xmlDocumentValidator.getXPathQueryHolder();
		xPathQueryHolders.clear();
		final XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		xPathQueryHolders.add(xPathQueryHolder);
		return xmlDocumentValidator;
	}

	/**
	 * Load the certificates (trust anchors) contained in all the TSL referenced by the LOTL
	 */
	public void init() {

		if (LOG.isInfoEnabled()) {
			LOG.info("TSL refresh policy: ", tslRefreshPolicy.name());
			LOG.info("TSL property cache folder: ", tslPropertyCacheFolder.getAbsolutePath());
		}

		diagnosticInfo.clear();

		final TrustStatusList lotl = loadLotl();
		final int size = lotl.getOtherTSLPointers().size();
		//        final ExecutorService executorService = Executors.newFixedThreadPool(size);
		//        List<Future> futures = new ArrayList<Future>(size);
		for (final PointerToOtherTSL pointerToTSL : lotl.getOtherTSLPointers()) {
			//            Runnable runnable = new Runnable() {
			//                public void run() {

			final String url = pointerToTSL.getTslLocation();
			final String territory = pointerToTSL.getTerritory();
			final List<X509Certificate> signingCertList = pointerToTSL.getDigitalIdentity();
			try {

				loadTSL(url, territory, signingCertList);
			} catch (DSSException e) {
				LOG.error("Error loading trusted list for {} at {}", new Object[]{territory, url, e});
				// do nothing continue with the next trusted list.
			}

			//                }
			//            };
			//            final Future submit = executorService.submit(runnable);
			//            futures.add(submit);
		}

		//        executorService.shutdown();
		//        while (!executorService.isTerminated()){
		//            try {
		//                Thread.sleep(100);
		//            } catch (InterruptedException e) {
		//                throw new RuntimeException(e);
		//            }
		//        }
		//        LOG.info("Parallel download of Trusted list done");
		loadAdditionalLists();
		LOG.info("Loading completed: {} trusted lists", size);
		LOG.info("                 : {} certificates", certPool.getNumberOfCertificates());
	}

	private TrustStatusList loadLotl() {

		X509Certificate lotlCert = null;
		if (checkSignature) {

			lotlCert = readLOTLCertificate();
		}
		TrustStatusList lotl;
		try {

			LOG.info("Downloading LOTL from url= {}", lotlUrl);
			final ArrayList<X509Certificate> x509CertificateList = new ArrayList<X509Certificate>();
			x509CertificateList.add(lotlCert);
			lotl = getTrustStatusList(lotlUrl, x509CertificateList);
		} catch (DSSException e) {

			LOG.error("The LOTL cannot be loaded: " + e.getMessage(), e);
			throw e;
		}
		diagnosticInfo.put(lotlUrl, "Loaded " + new Date().toString());
		return lotl;
	}

	private X509Certificate readLOTLCertificate() throws DSSException {

		X509Certificate lotlCert;
		if (lotlCertificate == null) {

			final String msg = "The LOTL signing certificate property must contain a reference to a certificate.";
			diagnosticInfo.put(lotlUrl, msg);
			throw new DSSException(msg);
		}
		InputStream inputStream = null;
		try {

			inputStream = getLotlCertificateInputStream();
			lotlCert = DSSUtils.loadCertificate(inputStream);
		} catch (DSSException e) {

			final String msg = "Cannot read LOTL signing certificate.";
			diagnosticInfo.put(lotlUrl, msg);
			throw e;
		} finally {

			DSSUtils.closeQuietly(inputStream);
		}
		return lotlCert;
	}

	/**
	 * This method gives the possibility to extend this class and to add other trusted lists. It is invoked systematically from {@code #init()} method.
	 *
	 * @param urls
	 */
	protected void loadAdditionalLists(final String... urls) {

	}

	/**
	 * This method allows to load any trusted list.
	 *
	 * @param url                 of the TSL to load
	 * @param territory           of the TSL
	 * @param signingCertificates the {@code List} of the possible signing certificates
	 */
	public void loadAdditionalList(final String url, final String territory, final List<X509Certificate> signingCertificates) {

		loadTSL(url, territory, signingCertificates);
	}

	/**
	 * @param url             of the TSL to load
	 * @param territory       of the TSL
	 * @param signingCertList the {@code List} of the possible signing certificates
	 */
	protected void loadTSL(final String url, final String territory, final List<X509Certificate> signingCertList) {

		if (DSSUtils.isBlank(url)) {

			LOG.error("The URL is blank!");
			return;
		}
		final String trimmedUrl = url.trim();
		try {

			diagnosticInfo.put(trimmedUrl, "Loading");
			LOG.info("Downloading TrustStatusList for '{}' from url= {}", territory, trimmedUrl);
			final TrustStatusList countryTSL = getTrustStatusList(trimmedUrl, signingCertList);
			loadAllCertificatesFromOneTSL(countryTSL);
			LOG.info(".... done for '{}'", territory);
			diagnosticInfo.put(trimmedUrl, "Loaded " + new Date().toString());
		} catch (final DSSNullReturnedException e) {

			LOG.info("Download skipped.");
			// do nothing: it can happened when a mock data loader is used.
		} catch (final Throwable e) {
			makeATrace(trimmedUrl, "Other problem: " + e.toString(), e);
		}
	}

	private void makeATrace(final String url, final String message, final Throwable e) {

		LOG.error(message, e);
		StringWriter w = new StringWriter();
		e.printStackTrace(new PrintWriter(w));
		diagnosticInfo.put(url, w.toString());
	}

	/**
	 * Adds all the service entries (current and history) of all the providers of the trusted list to the list of
	 * CertificateSource
	 *
	 * @param trustStatusList
	 */
	private void loadAllCertificatesFromOneTSL(final TrustStatusList trustStatusList) {

		for (final TrustServiceProvider trustServiceProvider : trustStatusList.getTrustServicesProvider()) {

			for (final AbstractTrustService trustService : trustServiceProvider.getTrustServiceList()) {

				if (LOG.isTraceEnabled()) {
					LOG.trace("#Service Name: " + trustService.getServiceName());
					LOG.trace("      ------> " + trustService.getType());
					LOG.trace("      ------> " + trustService.getStatus());
				}
				for (final Object digitalIdentity : trustService.getDigitalIdentity()) {

					try {

						X509Certificate x509Certificate = null;
						if (digitalIdentity instanceof X509Certificate) {

							x509Certificate = (X509Certificate) digitalIdentity;
						} else if (digitalIdentity instanceof X500Principal) {

							final X500Principal x500Principal = (X500Principal) digitalIdentity;
							final List<CertificateToken> certificateTokens = certPool.get(x500Principal);
							if (certificateTokens.size() > 0) {
								x509Certificate = certificateTokens.get(0).getCertificate();
							} else {
								LOG.debug("WARNING: There is currently no certificate with the given X500Principal: '{}' within the certificate pool!", x500Principal);
							}
						}
						if (x509Certificate != null) {

							addCertificate(x509Certificate, trustService, trustServiceProvider, trustStatusList.isWellSigned());
						}
					} catch (DSSException e) {

						// There is a problem when loading the certificate, we continue with the next one.
						LOG.warn(e.getLocalizedMessage());
					}
				}
			}
		}
	}

	/**
	 * This method allows to set the {@code RefreshPolicy} to be used when loading or re-loading the trusted lists.
	 *
	 * @param tslRefreshPolicy {@code RefreshPolicy} to use
	 */
	public void setTslRefreshPolicy(final TSLRefreshPolicy tslRefreshPolicy) {
		this.tslRefreshPolicy = tslRefreshPolicy;
	}

	/**
	 * Defines if the TL signature must be checked.
	 *
	 * @param checkSignature the checkSignature to set
	 */
	public void setCheckSignature(final boolean checkSignature) {
		this.checkSignature = checkSignature;
	}

	/**
	 * The path to the LOTL certificate can be provided in two manners by using {@code classpath://} or {@code file://} prefixes (Spring notation).
	 *
	 * @param lotlCertificate the path to the LOTL signing certificate to set
	 */
	public void setLotlCertificate(final String lotlCertificate) {
		this.lotlCertificate = lotlCertificate;
	}

	/**
	 * Define the URL of the LOTL
	 *
	 * @param lotlUrl the lotlUrl to set
	 */
	public void setLotlUrl(final String lotlUrl) {
		this.lotlUrl = lotlUrl;
	}

	/**
	 * @param dataLoader the dataLoader to set
	 */
	public void setDataLoader(final DataLoader dataLoader) {

		this.dataLoader = dataLoader;
		if (dataLoader instanceof CommonsDataLoader) {

			CommonsDataLoader commonsDataLoader1 = (CommonsDataLoader) dataLoader;
			commonsDataLoader.setProxyPreferenceManager(commonsDataLoader1.getProxyPreferenceManager());
			commonsDataLoader1.propagateAuthentication(commonsDataLoader);
		}
	}

	/**
	 * @param tslPropertyCacheFolder
	 */
	public void setTslPropertyCacheFolder(final File tslPropertyCacheFolder) {
		this.tslPropertyCacheFolder = tslPropertyCacheFolder;
	}

	/**
	 * @param propertiesFileName
	 * @return
	 */
	public Properties loadProperties(final String propertiesFileName) {

		final Properties properties = new Properties();
		final File file = new File(tslPropertyCacheFolder, propertiesFileName);
		if (file.exists()) {
			try {
				final InputStream inputStream = DSSUtils.toInputStream(file);
				properties.load(inputStream);
			} catch (Exception e) {
				LOG.error("Impossible to load: '{}'", file.getAbsolutePath(), e);
			}
		}
		return properties;
	}

	/**
	 * @param properties
	 * @param propertiesFileName
	 */
	public void saveProperties(final Properties properties, final String propertiesFileName) {

		final File file = new File(tslPropertyCacheFolder, propertiesFileName);
		try {

			final FileOutputStream fileOutputStream = new FileOutputStream(file);
			properties.store(fileOutputStream, null);
		} catch (Exception e) {
			LOG.error("Impossible to save: '{}'", file.getAbsolutePath(), e);
		}
	}
}
