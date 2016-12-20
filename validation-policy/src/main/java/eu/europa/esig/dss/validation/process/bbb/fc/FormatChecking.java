package eu.europa.esig.dss.validation.process.bbb.fc;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableMimetypeFileContentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.AcceptableZipCommentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ContainerTypeCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.FormatCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ManifestFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.MimeTypeFilePresentCheck;
import eu.europa.esig.dss.validation.process.bbb.fc.checks.ZipCommentPresentCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

/**
 * 5.2.2 Format Checking
 * 
 * This building block shall check that the signature to validate is conformant
 * to the applicable base format (e.g. CMS [i.8], CAdES [i.2], XML-DSig [i.11],
 * XAdES [i.4], etc.) prior to any subsequent processing.
 */
public class FormatChecking extends Chain<XmlFC> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	private final Context context;
	private final ValidationPolicy policy;

	public FormatChecking(DiagnosticData diagnosticData, SignatureWrapper signature, Context context, ValidationPolicy policy) {
		super(new XmlFC());

		this.diagnosticData = diagnosticData;
		this.signature = signature;
		this.context = context;
		this.policy = policy;
	}

	@Override
	protected void initChain() {
		ChainItem<XmlFC> item = firstItem = formatCheck();

		if (diagnosticData.isContainerInfoPresent()) {

			item = item.setNextItem(containerTypeCheck());

			item = item.setNextItem(zipCommentPresentCheck());

			item = item.setNextItem(acceptableZipCommentCheck());

			item = item.setNextItem(mimetypeFilePresentCheck());

			item = item.setNextItem(mimetypeFileContentCheck());

			item = item.setNextItem(manifestFilePresentCheck());
		}
	}

	private ChainItem<XmlFC> formatCheck() {
		MultiValuesConstraint constraint = policy.getSignatureFormatConstraint(context);
		return new FormatCheck(result, signature, constraint);
	}

	private ChainItem<XmlFC> containerTypeCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedContainerTypesConstraint();
		return new ContainerTypeCheck(result, diagnosticData.getContainerType(), constraint);
	}

	private ChainItem<XmlFC> zipCommentPresentCheck() {
		LevelConstraint constraint = policy.getZipCommentPresentConstraint();
		return new ZipCommentPresentCheck(result, diagnosticData.getZipComment(), constraint);
	}

	private ChainItem<XmlFC> acceptableZipCommentCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedZipCommentsConstraint();
		return new AcceptableZipCommentCheck(result, diagnosticData.getZipComment(), constraint);
	}

	private ChainItem<XmlFC> mimetypeFilePresentCheck() {
		LevelConstraint constraint = policy.getMimeTypeFilePresentConstraint();
		return new MimeTypeFilePresentCheck(result, diagnosticData.isMimetypeFilePresent(), constraint);
	}

	private ChainItem<XmlFC> mimetypeFileContentCheck() {
		MultiValuesConstraint constraint = policy.getAcceptedMimeTypeContentsConstraint();
		return new AcceptableMimetypeFileContentCheck(result, diagnosticData.getMimetypeFileContent(), constraint);
	}

	private ChainItem<XmlFC> manifestFilePresentCheck() {
		LevelConstraint constraint = policy.getManifestFilePresentConstraint();
		return new ManifestFilePresentCheck(result, diagnosticData.getContainerInfo(), constraint);
	}

}
