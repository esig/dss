package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.AbstractSignatureWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableMimetypeFileContentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableZipCommentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeAllDocumentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ByteRangeCollisionCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ContainerTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.DocMDPCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FieldMDPCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ManifestFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.MimeTypeFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PDFAComplianceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PDFAProfileCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfAnnotationOverlapCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfPageDifferenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfSignatureDictionaryCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.PdfVisualDifferenceCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SigFieldLockCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.SignedFilesPresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.UndefinedChangesCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ZipCommentPresentCheck;

/**
 * This class contains a common code to be processed as a part of a "5.2.2 Format Checking" building block
 * for validation of signatures and timestamps.
 *
 * @param <S> signature or timestamp wrapper
 */
public abstract class AbstractFormatChecking<S extends AbstractSignatureWrapper> extends Chain<XmlFC> {

    /** Diagnostic data */
    protected final DiagnosticData diagnosticData;

    /** The token to validate */
    protected final S token;

    /** The validation context */
    protected final Context context;

    /** The validation policy */
    protected final ValidationPolicy policy;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param token {@link AbstractSignatureWrapper}
     * @param context {@link Context}
     * @param policy {@link ValidationPolicy}
     */
    public AbstractFormatChecking(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                  S token, Context context, ValidationPolicy policy) {
        super(i18nProvider, new XmlFC());
        this.diagnosticData = diagnosticData;
        this.token = token;
        this.context = context;
        this.policy = policy;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.FORMAT_CHECKING;
    }

    /**
     * This method chains all PDF revision related checks to the given {@code item} chain, when applicable
     * 
     * @param item {@link ChainItem} to append PDF revision related checks
     * @return {@link ChainItem} with the PDF revision related checks
     */
    protected ChainItem<XmlFC> getPDFRevisionValidationChain(ChainItem<XmlFC> item) {

        PDFRevisionWrapper pdfRevision = token.getPDFRevision();

        if (pdfRevision != null) {

            if (item == null) {
                item = firstItem = byteRangeCheck();
            } else {
                item = item.setNextItem(byteRangeCheck());
            }

            item = item.setNextItem(byteRangeCollisionCheck());

            item = item.setNextItem(byteRangeAllDocumentCheck());

            item = item.setNextItem(pdfSignatureDictionaryCheck());

            item = item.setNextItem(pdfPageDifferenceCheck());

            item = item.setNextItem(pdfAnnotationOverlapCheck());

            item = item.setNextItem(pdfVisualDifferenceCheck());

            // /DocMDP check
            if (pdfRevision.getDocMDPPermissions() != null) {
                item = item.setNextItem(docMDPCheck());
            }
            // /FieldMDP
            if (pdfRevision.getFieldMDP() != null) {
                item = item.setNextItem(fieldMDPCheck());
            }
            // /SigFieldLock
            if (pdfRevision.getSigFieldLock() != null) {
                item = item.setNextItem(sigFieldLockCheck());
            }

            item = item.setNextItem(undefinedChangesCheck());

        }

        return item;

    }

    /**
     * This method chains all PDF/A related checks to the given {@code item} chain, when applicable
     *
     * @param item {@link ChainItem} to append PDF/A related checks
     * @return {@link ChainItem} with the PDF/A related checks
     */
    protected ChainItem<XmlFC> getPdfaValidationChain(ChainItem<XmlFC> item) {

        // executed only when dss-pdfa module has been loaded
        if (diagnosticData.isPDFAValidationPerformed()) {

            if (item == null) {
                item = firstItem = pdfaProfileCheck();
            } else {
                item = item.setNextItem(pdfaProfileCheck());
            }

            item = item.setNextItem(pdfaCompliantCheck());

        }

        return item;

    }

    /**
     * This method chains all ASiC container related checks to the given {@code item} chain, when applicable
     *
     * @param item {@link ChainItem} to append ASiC container related checks
     * @return {@link ChainItem} with the ASiC container related checks
     */
    protected ChainItem<XmlFC> getASiCContainerValidationChain(ChainItem<XmlFC> item) {

        if (diagnosticData.isContainerInfoPresent()) {

            if (item == null) {
                item = firstItem = containerTypeCheck();
            } else {
                item = item.setNextItem(containerTypeCheck());
            }

            item = item.setNextItem(zipCommentPresentCheck());

            if (Utils.isStringNotBlank(diagnosticData.getZipComment())) {

                item = item.setNextItem(acceptableZipCommentCheck());

            }

            item = item.setNextItem(mimetypeFilePresentCheck());

            if (diagnosticData.isMimetypeFilePresent()) {

                item = item.setNextItem(mimetypeFileContentCheck());

            }

            item = item.setNextItem(manifestFilePresentCheck());

            item = item.setNextItem(signedFilesPresentCheck());

        }

        return item;

    }

    private ChainItem<XmlFC> byteRangeCheck() {
        LevelConstraint constraint = policy.getByteRangeConstraint(context);
        return new ByteRangeCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> byteRangeCollisionCheck() {
        LevelConstraint constraint = policy.getByteRangeCollisionConstraint(context);
        return new ByteRangeCollisionCheck(i18nProvider, result, token, diagnosticData, constraint);
    }

    private ChainItem<XmlFC> byteRangeAllDocumentCheck() {
        LevelConstraint constraint = policy.getByteRangeAllDocumentConstraint(context);
        return new ByteRangeAllDocumentCheck(i18nProvider, result, diagnosticData, constraint);
    }

    private ChainItem<XmlFC> pdfSignatureDictionaryCheck() {
        LevelConstraint constraint = policy.getPdfSignatureDictionaryConstraint(context);
        return new PdfSignatureDictionaryCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> pdfPageDifferenceCheck() {
        LevelConstraint constraint = policy.getPdfPageDifferenceConstraint(context);
        return new PdfPageDifferenceCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> pdfAnnotationOverlapCheck() {
        LevelConstraint constraint = policy.getPdfAnnotationOverlapConstraint(context);
        return new PdfAnnotationOverlapCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> pdfVisualDifferenceCheck() {
        LevelConstraint constraint = policy.getPdfVisualDifferenceConstraint(context);
        return new PdfVisualDifferenceCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> docMDPCheck() {
        LevelConstraint constraint = policy.getDocMDPConstraint(context);
        return new DocMDPCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> fieldMDPCheck() {
        LevelConstraint constraint = policy.getFieldMDPConstraint(context);
        return new FieldMDPCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> sigFieldLockCheck() {
        LevelConstraint constraint = policy.getSigFieldLockConstraint(context);
        return new SigFieldLockCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> undefinedChangesCheck() {
        LevelConstraint constraint = policy.getUndefinedChangesConstraint(context);
        return new UndefinedChangesCheck(i18nProvider, result, token.getPDFRevision(), constraint);
    }

    private ChainItem<XmlFC> pdfaProfileCheck() {
        MultiValuesConstraint constraint = policy.getAcceptablePDFAProfilesConstraint();
        return new PDFAProfileCheck(i18nProvider, result, diagnosticData.getPDFAProfileId(), constraint);
    }

    private ChainItem<XmlFC> pdfaCompliantCheck() {
        LevelConstraint constraint = policy.getPDFACompliantConstraint();
        return new PDFAComplianceCheck(i18nProvider, result, diagnosticData.isPDFACompliant(), constraint);
    }

    private ChainItem<XmlFC> containerTypeCheck() {
        MultiValuesConstraint constraint = policy.getAcceptedContainerTypesConstraint();
        return new ContainerTypeCheck(i18nProvider, result, diagnosticData.getContainerType(), constraint);
    }

    private ChainItem<XmlFC> zipCommentPresentCheck() {
        LevelConstraint constraint = policy.getZipCommentPresentConstraint();
        return new ZipCommentPresentCheck(i18nProvider, result, diagnosticData.getZipComment(), constraint);
    }

    private ChainItem<XmlFC> acceptableZipCommentCheck() {
        MultiValuesConstraint constraint = policy.getAcceptedZipCommentsConstraint();
        return new AcceptableZipCommentCheck(i18nProvider, result, diagnosticData.getZipComment(), constraint);
    }

    private ChainItem<XmlFC> mimetypeFilePresentCheck() {
        LevelConstraint constraint = policy.getMimeTypeFilePresentConstraint();
        return new MimeTypeFilePresentCheck(i18nProvider, result, diagnosticData.isMimetypeFilePresent(), constraint);
    }

    private ChainItem<XmlFC> mimetypeFileContentCheck() {
        MultiValuesConstraint constraint = policy.getAcceptedMimeTypeContentsConstraint();
        return new AcceptableMimetypeFileContentCheck(i18nProvider, result, diagnosticData.getMimetypeFileContent(), constraint);
    }

    private ChainItem<XmlFC> manifestFilePresentCheck() {
        LevelConstraint constraint = policy.getManifestFilePresentConstraint();
        return new ManifestFilePresentCheck(i18nProvider, result, diagnosticData.getContainerInfo(), constraint);
    }

    private ChainItem<XmlFC> signedFilesPresentCheck() {
        LevelConstraint constraint = policy.getSignedFilesPresentConstraint();
        return new SignedFilesPresentCheck(i18nProvider, result, diagnosticData.getContainerInfo(), constraint);
    }

}
