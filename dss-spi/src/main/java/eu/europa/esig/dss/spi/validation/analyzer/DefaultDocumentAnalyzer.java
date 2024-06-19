package eu.europa.esig.dss.spi.validation.analyzer;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.model.signature.SignaturePolicyValidationResult;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationData;
import eu.europa.esig.dss.spi.validation.ValidationDataContainer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;
import eu.europa.esig.dss.spi.validation.analyzer.timestamp.TimestampAnalyzer;
import eu.europa.esig.dss.spi.validation.executor.DefaultValidationContextExecutor;
import eu.europa.esig.dss.spi.validation.executor.ValidationContextExecutor;
import eu.europa.esig.dss.spi.validation.scope.EvidenceRecordScopeFinder;
import eu.europa.esig.dss.spi.validation.timestamp.DetachedTimestampSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class contains a common code for processing of signed documents
 *
 */
public abstract class DefaultDocumentAnalyzer implements DocumentAnalyzer {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultDocumentAnalyzer.class);

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
    }

    /**
     * The document to be validated (with the signature(s) or timestamp(s))
     */
    protected DSSDocument document;

    /**
     * In case of a detached signature this {@code List} contains the signed
     * documents.
     */
    protected List<DSSDocument> detachedContents = new ArrayList<>();

    /**
     * Contains a list of evidence record documents detached from the signature
     */
    protected List<DSSDocument> detachedEvidenceRecordDocuments = new ArrayList<>();

    /**
     * In case of an ASiC signature this {@code List} of container documents.
     */
    protected List<DSSDocument> containerContents;

    /**
     * A related {@link ManifestFile} to the provided {@code document}
     */
    protected ManifestFile manifestFile;

    /**
     * Certificate source to find signing certificate
     */
    protected CertificateSource signingCertificateSource;

    /**
     * A time to validate the document against
     */
    private Date validationTime;

    /**
     * The reference to the certificate verifier. The current DSS implementation
     * proposes {@link eu.europa.esig.dss.spi.validation.CommonCertificateVerifier}.
     * This verifier encapsulates the references to different sources used in the
     * signature validation process.
     */
    protected CertificateVerifier certificateVerifier;

    /**
     * Performs validation of {@code ValidationContext}
     * Default : {@code DefaultValidationContextExecutor}
     */
    private ValidationContextExecutor validationContextExecutor = DefaultValidationContextExecutor.INSTANCE;

    /**
     * The implementation to be used for identifiers generation
     */
    private TokenIdentifierProvider tokenIdentifierProvider = new OriginalIdentifierProvider();

    /**
     * Provides methods to extract a policy content by its identifier
     */
    private SignaturePolicyProvider signaturePolicyProvider;

    /**
     * Cached list of signatures extracted from the document
     */
    private List<AdvancedSignature> signatures;

    /**
     * Cached list of detached timestamps extracted from the document
     */
    private List<TimestampToken> detachedTimestamps;

    /**
     * Cached list of detached evidence records extracted from the document
     */
    private List<EvidenceRecord> evidenceRecords;

    /**
     * The default constructor
     */
    protected DefaultDocumentAnalyzer() {
        // empty
    }

    /**
     * This method guesses the document format and returns an appropriate
     * document reader.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@code DocumentReader} in terms
     *         of the document type
     */
    public static DocumentAnalyzer fromDocument(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "DSSDocument is null");
        ServiceLoader<DocumentAnalyzerFactory> serviceLoaders = ServiceLoader.load(DocumentAnalyzerFactory.class);
        for (DocumentAnalyzerFactory factory : serviceLoaders) {
            if (factory.isSupported(dssDocument)) {
                return factory.create(dssDocument);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    @Override
    public DSSDocument getDocument() {
        if (document == null) {
            throw new IllegalStateException("Document is not provided! " +
                    "Please use a different constructor to extract the document.");
        }
        return document;
    }

    @Override
    public void setSigningCertificateSource(CertificateSource signingCertificateSource) {
        this.signingCertificateSource = signingCertificateSource;
    }

    /**
     * To carry out the validation process of the signature(s) some external sources
     * of certificates and of revocation data can be needed. The certificate
     * verifier is used to pass these values. Note that once this setter is called
     * any change in the content of the <code>CommonTrustedCertificateSource</code>
     * or in adjunct certificate source is not taken into account.
     *
     * @param certificateVerifier {@link CertificateVerifier}
     */
    @Override
    public void setCertificateVerifier(final CertificateVerifier certificateVerifier) {
        Objects.requireNonNull(certificateVerifier);
        this.certificateVerifier = certificateVerifier;
    }

    @Override
    public void setValidationContextExecutor(ValidationContextExecutor validationContextExecutor) {
        this.validationContextExecutor = validationContextExecutor;
    }

    /**
     * Gets {@code TokenIdentifierProvider}
     *
     * @return {@link TokenIdentifierProvider}
     */
    public TokenIdentifierProvider getTokenIdentifierProvider() {
        return tokenIdentifierProvider;
    }

    @Override
    public void setTokenIdentifierProvider(TokenIdentifierProvider tokenIdentifierProvider) {
        Objects.requireNonNull(tokenIdentifierProvider);
        this.tokenIdentifierProvider = tokenIdentifierProvider;
    }

    @Override
    public void setDetachedContents(final List<DSSDocument> detachedContents) {
        this.detachedContents = detachedContents;
    }

    @Override
    public void setDetachedEvidenceRecordDocuments(final List<DSSDocument> detachedEvidenceRecordDocuments) {
        this.detachedEvidenceRecordDocuments = detachedEvidenceRecordDocuments;
    }

    @Override
    public void setContainerContents(List<DSSDocument> containerContents) {
        this.containerContents = containerContents;
    }

    @Override
    public void setManifestFile(ManifestFile manifestFile) {
        this.manifestFile = manifestFile;
    }

    /**
     * Returns validation time In case if the validation time is not provided,
     * initialize the current time value from the system
     *
     * @return {@link Date} validation time
     */
    public Date getValidationTime() {
        if (validationTime == null) {
            validationTime = new Date();
        }
        return validationTime;
    }

    /**
     * Allows to define a custom validation time
     *
     * @param validationTime {@link Date}
     */
    @Override
    public void setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
    }

    /**
     * Sets a list of detached evidence records
     *
     * @param evidenceRecords a list of {@link EvidenceRecord}s
     */
    public void setDetachedEvidenceRecords(List<EvidenceRecord> evidenceRecords) {
        this.evidenceRecords = evidenceRecords;
    }

    /**
     * Returns a signaturePolicyProvider If not defined, returns a default provider
     *
     * @return {@link SignaturePolicyProvider}
     */
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        if (signaturePolicyProvider == null) {
            LOG.info("Default SignaturePolicyProvider instantiated with NativeHTTPDataLoader.");
            signaturePolicyProvider = new SignaturePolicyProvider();
            signaturePolicyProvider.setDataLoader(new NativeHTTPDataLoader());
        }
        return signaturePolicyProvider;
    }

    @Override
    public void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider) {
        this.signaturePolicyProvider = signaturePolicyProvider;
    }

    @Override
    public ValidationContext validate() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
        Objects.requireNonNull(document, "Document is not provided to the validator");

        List<AdvancedSignature> allSignatures = getAllSignatures();
        List<TimestampToken> detachedTimestamps = getDetachedTimestamps();
        List<EvidenceRecord> detachedEvidenceRecords = getDetachedEvidenceRecords();

        final CertificateVerifier certificateVerifierForValidation =
                new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopyForValidation();
        final ValidationContext validationContext = prepareValidationContext(
                allSignatures, detachedTimestamps, detachedEvidenceRecords, certificateVerifierForValidation);
        validateContext(validationContext);
        return validationContext;
    }

    /**
     * Initializes and fills {@code ValidationContext} with necessary data sources
     *
     * @param <T> {@link AdvancedSignature} implementation
     * @param signatures a collection of {@link AdvancedSignature}s
     * @param detachedTimestamps a collection of detached {@link TimestampToken}s
     * @param detachedEvidenceRecords a collection of detached {@link EvidenceRecord}s
     * @param certificateVerifier {@link CertificateVerifier} to be used for the validation
     * @return {@link ValidationContext}
     */
    protected <T extends AdvancedSignature> ValidationContext prepareValidationContext(
            final Collection<T> signatures, final Collection<TimestampToken> detachedTimestamps,
            final Collection<EvidenceRecord> detachedEvidenceRecords,
            final CertificateVerifier certificateVerifier) {
        final ValidationContext validationContext = createValidationContext();
        validationContext.initialize(certificateVerifier);
        prepareSignatureValidationContext(validationContext, signatures);
        prepareDetachedTimestampValidationContext(validationContext, detachedTimestamps);
        prepareDetachedEvidenceRecordValidationContext(validationContext, detachedEvidenceRecords);
        return validationContext;
    }

    /**
     * This method creates a new instance of {@code ValidationContext} performing preparation of validation data,
     * certificate chain building, revocation request, as well as custom validation checks execution.
     *
     * @return {@link ValidationContext}
     */
    protected ValidationContext createValidationContext() {
        return new SignatureValidationContext(getValidationTime());
    }

    @Override
    public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures) {
        return getValidationData(signatures, Collections.emptyList());
    }

    @Override
    public <T extends AdvancedSignature> ValidationDataContainer getValidationData(Collection<T> signatures,
                                                                                   Collection<TimestampToken> detachedTimestamps) {
        if (Utils.isCollectionEmpty(signatures) && Utils.isCollectionEmpty(detachedTimestamps)) {
            throw new DSSException("At least one signature or a timestamp shall be provided to extract the validation data!");
        }

        // TODO : review use of evidence records
        ValidationContext validationContext = prepareValidationContext(
                signatures, detachedTimestamps, Collections.emptyList(), certificateVerifier);
        validateContext(validationContext);

        ValidationDataContainer validationDataContainer = instantiateValidationDataContainer();
        for (AdvancedSignature signature : signatures) {
            ValidationData signatureValidationData = validationContext.getValidationData(signature);
            validationDataContainer.addValidationData(signature, signatureValidationData);
            for (TimestampToken timestampToken : signature.getAllTimestamps()) {
                ValidationData timestampValidationData = validationContext.getValidationData(timestampToken);
                validationDataContainer.addValidationData(timestampToken, timestampValidationData);
            }
            for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
                ValidationData counterSignatureValidationData = validationContext.getValidationData(counterSignature);
                validationDataContainer.addValidationData(counterSignature, counterSignatureValidationData);
            }
        }
        for (TimestampToken detachedTimestamp : detachedTimestamps) {
            ValidationData timestampValidationData = validationContext.getValidationData(detachedTimestamp);
            validationDataContainer.addValidationData(detachedTimestamp, timestampValidationData);
        }

        return validationDataContainer;
    }

    /**
     * Creates a new instance of {@code ValidationDataContainer}
     *
     * @return {@link ValidationDataContainer}
     */
    protected ValidationDataContainer instantiateValidationDataContainer() {
        return new ValidationDataContainer();
    }

    /**
     * Returns a list of all found evidence records (embedded and detached)
     *
     * @param signatures a list of {@link AdvancedSignature}s
     * @param detachedEvidenceRecords a list of detached {@code EvidenceRecord}s
     * @return a list of all {@link EvidenceRecord}s
     */
    protected List<EvidenceRecord> getAllEvidenceRecords(final List<AdvancedSignature> signatures,
                                                         final List<EvidenceRecord> detachedEvidenceRecords) {
        List<EvidenceRecord> result = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            result.addAll(signature.getEmbeddedEvidenceRecords());
        }
        result.addAll(detachedEvidenceRecords);
        return result;
    }

    /**
     * Prepares the {@code validationContext} for signature validation process
     *
     * @param <T>
     *                          {@link AdvancedSignature} implementation
     * @param validationContext
     *                          {@link ValidationContext}
     * @param allSignatures
     *                          a collection of all {@link AdvancedSignature}s to be
     *                          validated
     */
    protected <T extends AdvancedSignature> void prepareSignatureValidationContext(
            final ValidationContext validationContext, final Collection<T> allSignatures) {
        prepareSignatureForVerification(validationContext, allSignatures);
        processSignaturesValidation(allSignatures);
    }

    /**
     * This method prepares a {@code SignatureValidationContext} for signatures validation
     *
     * @param <T>
     *                          {@link AdvancedSignature} implementation
     * @param allSignatureList  {@code Collection} of {@code AdvancedSignature}s to
     *                          validate including the countersignatures
     * @param validationContext {@code ValidationContext} is the implementation of
     *                          the validators for: certificates, timestamps and
     *                          revocation data.
     */
    protected <T extends AdvancedSignature> void prepareSignatureForVerification(
            final ValidationContext validationContext, final Collection<T> allSignatureList) {
        for (final AdvancedSignature signature : allSignatureList) {
            validationContext.addSignatureForVerification(signature);
        }
    }

    /**
     * Prepares the {@code validationContext} for a timestamp validation process
     *
     * @param validationContext
     *                          {@link ValidationContext}
     * @param timestamps
     *                          a collection of detached timestamps
     */
    protected void prepareDetachedTimestampValidationContext(
            final ValidationContext validationContext, Collection<TimestampToken> timestamps) {
        for (TimestampToken timestampToken : timestamps) {
            validationContext.addTimestampTokenForVerification(timestampToken);
        }
    }

    /**
     * Prepares the {@code validationContext} for the evidence record validation process
     *
     * @param validationContext
     *                          {@link ValidationContext}
     * @param evidenceRecords
     *                          a collection of detached evidence records
     */
    protected void prepareDetachedEvidenceRecordValidationContext(
            final ValidationContext validationContext, Collection<EvidenceRecord> evidenceRecords) {
        for (EvidenceRecord evidenceRecord : evidenceRecords) {
            validationContext.addEvidenceRecordForVerification(evidenceRecord);
        }
    }

    /**
     * Process the validation
     *
     * @param validationContext {@link ValidationContext} to process
     */
    protected void validateContext(final ValidationContext validationContext) {
        validationContextExecutor.validate(validationContext);
    }

    /**
     * Returns an instance of a corresponding to the format {@code SignaturePolicyValidatorLoader}
     *
     * @return {@link SignaturePolicyValidatorLoader}
     */
    public SignaturePolicyValidatorLoader getSignaturePolicyValidatorLoader() {
        return new DefaultSignaturePolicyValidatorLoader();
    }

    /**
     * Returns a list of all signatures from the validating document
     *
     * @return a list of {@link AdvancedSignature}s
     */
    protected List<AdvancedSignature> getAllSignatures() {
        final List<AdvancedSignature> allSignatureList = new ArrayList<>();
        for (final AdvancedSignature signature : getSignatures()) {
            allSignatureList.add(signature);
            appendCounterSignatures(allSignatureList, signature);
        }
        appendExternalEvidenceRecords(allSignatureList);
        return allSignatureList;
    }

    /**
     * The util method to link counter signatures with the related master signatures
     *
     * @param allSignatureList a list of {@link AdvancedSignature}s
     * @param signature current {@link AdvancedSignature}
     */
    protected void appendCounterSignatures(final List<AdvancedSignature> allSignatureList,
                                           final AdvancedSignature signature) {
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            counterSignature.initBaselineRequirementsChecker(certificateVerifier);
            validateSignaturePolicy(counterSignature);
            allSignatureList.add(counterSignature);

            appendCounterSignatures(allSignatureList, counterSignature);
        }
    }

    /**
     * Appends detached evidence record provided to the validator to
     * the corresponding signatures covering by the evidence record document
     *
     * @param allSignatureList a list of {@link AdvancedSignature}s
     */
    protected void appendExternalEvidenceRecords(List<AdvancedSignature> allSignatureList) {
        List<EvidenceRecord> detachedEvidenceRecords = getDetachedEvidenceRecords();
        if (Utils.isCollectionNotEmpty(detachedEvidenceRecords) && Utils.isCollectionNotEmpty(allSignatureList)) {
            for (AdvancedSignature signature : allSignatureList) {
                for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
                    if (coversSignature(signature, evidenceRecord)) {
                        signature.addExternalEvidenceRecord(evidenceRecord);
                    }
                }
            }
        }
    }

    /**
     * Appends the detached evidence records covering the time-stamp
     *
     * @param timestampToken {@link TimestampToken}
     */
    protected void appendExternalEvidenceRecords(TimestampToken timestampToken) {
        DetachedTimestampSource detachedTimestampSource = new DetachedTimestampSource(timestampToken);
        for (EvidenceRecord evidenceRecord : getDetachedEvidenceRecords()) {
            if (isTimestampCoveredByEvidenceRecord(timestampToken, evidenceRecord)) {
                timestampToken.addDetachedEvidenceRecord(evidenceRecord);
                detachedTimestampSource.addExternalEvidenceRecord(evidenceRecord);
            }
        }
    }

    /**
     * Checks whether the {@code timestampToken} is covered by the given {@code evidenceRecord}
     *
     * @param timestampToken {@link TimestampToken}
     * @param evidenceRecord {@link EvidenceRecord}
     * @return TRUE if the time-stamp is covered by the evidence record, FALSE otherwise
     */
    protected boolean isTimestampCoveredByEvidenceRecord(TimestampToken timestampToken, EvidenceRecord evidenceRecord) {
        // true by default
        return true;
    }

    /**
     * Verifies whether an {@code evidenceRecord} covers the {@code signature}
     *
     * @param signature {@link AdvancedSignature}
     * @param evidenceRecord {@link EvidenceRecord}
     * @return TRUE if the evidence record covers the signature file, FALSE otherwise
     */
    protected boolean coversSignature(AdvancedSignature signature, EvidenceRecord evidenceRecord) {
        // return true by default
        return true;
    }

    @Override
    public List<AdvancedSignature> getSignatures() {
        if (signatures == null) {
            signatures = buildSignatures();
        }
        // delegated in CommonSignatureValidator
        return signatures;
    }

    /**
     * This method build a list of signatures to be extracted from a document
     *
     * @return a list of {@link AdvancedSignature}s
     */
    protected List<AdvancedSignature> buildSignatures() {
        // not implemented by default
        return Collections.emptyList();
    }

    @Override
    public List<TimestampToken> getDetachedTimestamps() {
        if (detachedTimestamps == null) {
            detachedTimestamps = buildDetachedTimestamps();
        }
        return detachedTimestamps;
    }

    /**
     * Builds a list of detached {@code TimestampToken}s extracted from the document
     *
     * @return a list of {@code TimestampToken}s
     */
    protected List<TimestampToken> buildDetachedTimestamps() {
        return Collections.emptyList();
    }

    /**
     * Returns a list of timestamp validators for timestamps embedded into the container
     *
     * @return a list of {@link TimestampAnalyzer}s
     */
    protected List<TimestampAnalyzer> getTimestampReaders() {
        // nothing by default
        return Collections.emptyList();
    }

    @Override
    public List<EvidenceRecord> getDetachedEvidenceRecords() {
        if (evidenceRecords == null) {
            evidenceRecords = buildDetachedEvidenceRecords();
        }
        return evidenceRecords;
    }

    /**
     * Builds a list of detached {@code EvidenceRecord}s extracted from the document
     *
     * @return a list of {@code EvidenceRecord}s
     */
    protected List<EvidenceRecord> buildDetachedEvidenceRecords() {
        if (Utils.isCollectionNotEmpty(detachedEvidenceRecordDocuments)) {
            List<EvidenceRecord> result = new ArrayList<>();
            for (DSSDocument evidenceRecordDocument : detachedEvidenceRecordDocuments) {
                EvidenceRecord evidenceRecord = buildEvidenceRecord(evidenceRecordDocument);
                if (evidenceRecord != null) {
                    result.add(evidenceRecord);
                }
            }
            return result;
        }
        return Collections.emptyList();
    }

    /**
     * Builds an evidence record from the given {@code DSSDocument}
     *
     * @param evidenceRecordDocument {@link DSSDocument} containing an evidence record
     * @return {@link EvidenceRecord}
     */
    protected EvidenceRecord buildEvidenceRecord(DSSDocument evidenceRecordDocument) {
        try {
            try {
                EvidenceRecordAnalyzer evidenceRecordAnalyzer = EvidenceRecordAnalyzerFactory.fromDocument(evidenceRecordDocument);
                evidenceRecordAnalyzer.setDetachedContents(getSignatureEvidenceRecordDetachedContents());
                evidenceRecordAnalyzer.setCertificateVerifier(certificateVerifier);
                return getEvidenceRecord(evidenceRecordAnalyzer);

            } catch (UnsupportedOperationException e) {
                LOG.warn("An error occurred on attempt to read an evidence record document with name '{}' : {}. " +
                        "Please ensure the corresponding module is loaded.", evidenceRecordDocument.getName(), e.getMessage());
            }
        } catch (Exception e) {
            LOG.warn("An error occurred on attempt to read an evidence record document with name '{}' : {}",
                    evidenceRecordDocument.getName(), e.getMessage(), e);
        }
        return null;
    }

    private List<DSSDocument> getSignatureEvidenceRecordDetachedContents() {
        List<DSSDocument> erDetachedContents = new ArrayList<>();
        erDetachedContents.add(document);
        if (Utils.isCollectionNotEmpty(detachedContents)) {
            erDetachedContents.addAll(detachedContents);
        }
        return erDetachedContents;
    }

    /**
     * Gets an evidence record from a {@code evidenceRecordReader}
     *
     * @param evidenceRecordReader {@link EvidenceRecordAnalyzer}
     * @return {@link EvidenceRecord}
     */
    protected EvidenceRecord getEvidenceRecord(EvidenceRecordAnalyzer evidenceRecordReader) {
        EvidenceRecord evidenceRecord = evidenceRecordReader.getEvidenceRecord();
        if (evidenceRecord != null) {
            List<SignatureScope> evidenceRecordScopes = getEvidenceRecordScopes(evidenceRecord);
            evidenceRecord.setEvidenceRecordScopes(evidenceRecordScopes);
            evidenceRecord.setTimestampedReferences(getTimestampedReferences(evidenceRecordScopes));
            return evidenceRecord;
        }
        return null;
    }

    /**
     * Finds evidence record scopes
     *
     * @param evidenceRecord {@link EvidenceRecord}
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getEvidenceRecordScopes(EvidenceRecord evidenceRecord) {
        return new EvidenceRecordScopeFinder(evidenceRecord).findEvidenceRecordScope();
    }

    /**
     * Performs cryptographic validation of the signatures
     *
     * @param allSignatureList a collection of {@link AdvancedSignature}s
     * @param <T> {@link AdvancedSignature}
     */
    protected <T extends AdvancedSignature> void processSignaturesValidation(Collection<T> allSignatureList) {
        for (final AdvancedSignature signature : allSignatureList) {
            signature.checkSignatureIntegrity();
        }
    }

    /**
     * Returns a list of timestamped references from the given list of {@code SignatureScope}s
     *
     * @param signatureScopes a list of {@link SignatureScope}s
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getTimestampedReferences(List<SignatureScope> signatureScopes) {
        List<TimestampedReference> timestampedReferences = new ArrayList<>();
        if (Utils.isCollectionNotEmpty(signatureScopes)) {
            for (SignatureScope signatureScope : signatureScopes) {
                if (addReference(signatureScope)) {
                    timestampedReferences.add(new TimestampedReference(
                            signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
                }
            }
        }
        return timestampedReferences;
    }

    /**
     * Checks if the signature scope shall be added as a timestamped reference
     * NOTE: used to avoid duplicates in ASiC with CAdES validator, due to covered signature/timestamp files
     *
     * @param signatureScope {@link SignatureScope} to check
     * @return TRUE if the timestamped reference shall be created for the given {@link SignatureScope}, FALSE otherwise
     */
    protected boolean addReference(SignatureScope signatureScope) {
        // accept all by default
        return true;
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(String signatureId) {
        AdvancedSignature advancedSignature = getSignatureById(signatureId);
        if (advancedSignature != null) {
            return getOriginalDocuments(advancedSignature);
        }
        return Collections.emptyList();
    }

    /**
     * Returns the signature with the given id. Processes custom {@code TokenIdentifierProvider} and counter signatures
     *
     * @param signatureId {@link String} id of a signature to be extracted
     * @return {@link AdvancedSignature} with the given id if found, NULL otherwise
     */
    public AdvancedSignature getSignatureById(String signatureId) {
        Objects.requireNonNull(signatureId, "Signature Id cannot be null!");
        for (AdvancedSignature advancedSignature : getSignatures()) {
            AdvancedSignature signature = findSignatureRecursively(advancedSignature, signatureId);
            if (signature != null) {
                return signature;
            }
        }
        return null;
    }

    private AdvancedSignature findSignatureRecursively(AdvancedSignature signature, String signatureId) {
        if (doesIdMatch(signature, signatureId)) {
            return signature;
        }
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            AdvancedSignature advancedSignature = findSignatureRecursively(counterSignature, signatureId);
            if (advancedSignature != null) {
                return advancedSignature;
            }
        }
        return null;
    }

    private boolean doesIdMatch(AdvancedSignature signature, String signatureId) {
        return signatureId.equals(signature.getId()) || signatureId.equals(signature.getDAIdentifier()) ||
                signatureId.equals(tokenIdentifierProvider.getIdAsString(signature));
    }

    /**
     * This method is used to perform validation of the signature policy's identifier, when present
     *
     * @param signature {@link AdvancedSignature}, which policy will be verified
     */
    protected void validateSignaturePolicy(AdvancedSignature signature) {
        SignaturePolicy signaturePolicy = signature.getSignaturePolicy();
        if (signaturePolicy != null) {
            SignaturePolicyStore signaturePolicyStore = signature.getSignaturePolicyStore();
            DSSDocument policyContent = extractSignaturePolicyContent(signaturePolicy, signaturePolicyStore);
            signaturePolicy.setPolicyContent(policyContent);

            SignaturePolicyValidator signaturePolicyValidator = getSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);

            SignaturePolicyValidationResult validationResult = signaturePolicyValidator.validate(signaturePolicy);
            signaturePolicy.setValidationResult(validationResult);
        }
    }

    private DSSDocument extractSignaturePolicyContent(SignaturePolicy signaturePolicy, SignaturePolicyStore signaturePolicyStore) {
        if (signaturePolicyStore != null) {
            if (signaturePolicyStore.getSignaturePolicyContent() != null) {
                return signaturePolicyStore.getSignaturePolicyContent();
            } else if (signaturePolicyStore.getSigPolDocLocalURI() != null && signaturePolicyProvider != null) {
                return signaturePolicyProvider.getSignaturePolicyByUrl(signaturePolicyStore.getSigPolDocLocalURI());
            }
        }
        if (signaturePolicyProvider != null) {
            return signaturePolicyProvider.getSignaturePolicy(signaturePolicy.getIdentifier(), signaturePolicy.getUri());
        }
        return null;
    }

}
