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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("slow")
public class PAdESLevelBSignWithFileMemoryUsageSettingTest extends AbstractPAdESTestSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBSignWithFileMemoryUsageSettingTest.class);

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File(PAdESLevelBSignWithFileMemoryUsageSettingTest.class.getClassLoader().getResource("./big_file.pdf").toURI()));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());
	}

	@Override
	protected DSSDocument sign() {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
		tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

		attemptFreeRuntimeMemory();

		// Run first time in order to load all classes -> first run takes more time
		CompleteSignProcessResult memoryFullSignResult = doAllSigns(PdfMemoryUsageSetting.memoryFull(), tempFileResourcesHandlerBuilder);
		List<StepWithProfilingResult<?>> memoryFullPerfTable = memoryFullSignResult.stepWithProfilingResults;

		attemptFreeRuntimeMemory();

		// re-run memory full mode for a more accurate result
		memoryFullSignResult = doAllSigns(PdfMemoryUsageSetting.memoryFull(), tempFileResourcesHandlerBuilder);
		memoryFullPerfTable = memoryFullSignResult.stepWithProfilingResults;

		attemptFreeRuntimeMemory();

		CompleteSignProcessResult memoryBufferedSignResult = doAllSigns(PdfMemoryUsageSetting.memoryBuffered(), tempFileResourcesHandlerBuilder);
		List<StepWithProfilingResult<?>> memoryBufferedPerfTable = memoryBufferedSignResult.stepWithProfilingResults;

		attemptFreeRuntimeMemory();

		CompleteSignProcessResult fileOnlySignTuple = doAllSigns(PdfMemoryUsageSetting.fileOnly(), tempFileResourcesHandlerBuilder);
		List<StepWithProfilingResult<?>> fileOnlyPerfTable = fileOnlySignTuple.stepWithProfilingResults;

		String leftAlignFormat = "| %-15.15s | %-15.15s | %,06.01f | %-12.12s |%n";

		System.out.format("+-----------------+-----------------+--------+--------------+%n");
		System.out.format("|                 | Step Name       | RAM    | Time spent   +%n");
		System.out.format("+-----------------+-----------------+--------+--------------+%n");
		for (int i = 0; i < fileOnlyPerfTable.size(); i++) {
			StepWithProfilingResult<?> stepPerf = memoryFullPerfTable.get(i);
			System.out.format(leftAlignFormat, "Memory Full", stepPerf.stepName, stepPerf.memoryDifference, stepPerf.timeDifference);

			stepPerf = memoryBufferedPerfTable.get(i);
			System.out.format(leftAlignFormat, "Memory Buffered", stepPerf.stepName, stepPerf.memoryDifference, stepPerf.timeDifference);

			stepPerf = fileOnlyPerfTable.get(i);
			System.out.format(leftAlignFormat, "File", stepPerf.stepName, stepPerf.memoryDifference, stepPerf.timeDifference);
		}
		System.out.format("+-----------------+-----------------+--------+--------------+%n");

		File ltaSignatureFile = fileOnlySignTuple.finalFile;

//		assertEquals(memoryOnlyMemoryConsumptions.size(), fileOnlyMemoryConsumptions.size());

		double memoryFullMemoryConsumptionsSum = memoryFullPerfTable.stream().mapToDouble(a -> a.memoryDifference).sum();
		double fileOnlyMemoryConsumptionsSum = fileOnlyPerfTable.stream().mapToDouble(a -> a.memoryDifference).sum();
		double difference = memoryFullMemoryConsumptionsSum - fileOnlyMemoryConsumptionsSum;
		LOG.info("Memory Sum difference is: {}Mb", difference);
//		assertTrue(difference > 0);

		assertTrue(ltaSignatureFile.exists());

		File tempFile = null;
		try {
			tempFile = Files.createTempFile("dss", ".pdf").toFile();
			try (InputStream is = Files.newInputStream(ltaSignatureFile.toPath()); OutputStream os = Files.newOutputStream(tempFile.toPath())) {
				Utils.copy(is, os);
			}

		} catch (IOException e) {
			fail(e);
		}

		assertTrue(ltaSignatureFile.exists());

		assertNotNull(tempFile);
		assertTrue(tempFile.exists());

		tempFileResourcesHandlerBuilder.clear();

		assertFalse(ltaSignatureFile.exists());
		assertTrue(tempFile.exists());

		return new FileDocument(tempFile);
	}

	@Override
	protected Reports validateDocument(DocumentValidator validator) {
		attemptFreeRuntimeMemory();
		// Run first time in order to load all classes -> first run takes more time
		ValidateProcessResult memoryFullValidateResult = doValidate(validator, PdfMemoryUsageSetting.memoryFull());
		StepWithProfilingResult<?> memoryFullPerfTable = memoryFullValidateResult.stepWithProfilingResult;

		attemptFreeRuntimeMemory();

		// re-run memory full mode for a more accurate result
		memoryFullValidateResult = doValidate(validator, PdfMemoryUsageSetting.memoryFull());
		memoryFullPerfTable = memoryFullValidateResult.stepWithProfilingResult;

		attemptFreeRuntimeMemory();

		ValidateProcessResult memoryBufferedValidateResult = doValidate(validator, PdfMemoryUsageSetting.memoryBuffered());
		StepWithProfilingResult<?> memoryBufferedPerfTable = memoryBufferedValidateResult.stepWithProfilingResult;

		attemptFreeRuntimeMemory();

		ValidateProcessResult fileOnlyValidateTuple = doValidate(validator, PdfMemoryUsageSetting.fileOnly());
		StepWithProfilingResult<?> fileOnlyPerfTable = fileOnlyValidateTuple.stepWithProfilingResult;

		String leftAlignFormat = "| %-15.15s | %-15.15s | %,06.01f | %-12.12s |%n";

		System.out.format("+-----------------+-----------------+--------+--------------+%n");
		System.out.format("|                 | Step Name       | RAM    | Time spent   +%n");
		System.out.format("+-----------------+-----------------+--------+--------------+%n");

		System.out.format(leftAlignFormat, "Memory Full", memoryFullPerfTable.stepName, memoryFullPerfTable.memoryDifference, memoryFullPerfTable.timeDifference);
		System.out.format(leftAlignFormat, "Memory Buffered", memoryBufferedPerfTable.stepName, memoryBufferedPerfTable.memoryDifference, memoryBufferedPerfTable.timeDifference);
		System.out.format(leftAlignFormat, "File", fileOnlyPerfTable.stepName, fileOnlyPerfTable.memoryDifference, fileOnlyPerfTable.timeDifference);

		System.out.format("+-----------------+-----------------+--------+--------------+%n");

		return fileOnlyValidateTuple.reports;
	}

	private ValidateProcessResult doValidate(DocumentValidator validator, PdfMemoryUsageSetting pdfMemoryUsageSetting) {
		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		pdfObjFactory.setPdfMemoryUsageSetting(pdfMemoryUsageSetting);

		PDFDocumentValidator pdfDocumentValidator = (PDFDocumentValidator) validator;
		pdfDocumentValidator.setPdfObjFactory(pdfObjFactory);

		StepWithProfilingResult<Reports> validateDocument = runStepWithProfiling("validateDocument", pdfDocumentValidator::validateDocument, pdfMemoryUsageSetting.getMode());
		return new ValidateProcessResult(validateDocument.result, validateDocument);
	}

	private CompleteSignProcessResult doAllSigns(PdfMemoryUsageSetting pdfMemoryUsageSetting, TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder) {
		PAdESService service = getService();
		PAdESSignatureParameters params = getSignatureParameters();
		DSSDocument toBeSigned = getDocumentToSign();

		List<StepWithProfilingResult<?>> stepPerfList = new ArrayList<>();

		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		pdfObjFactory.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
		pdfObjFactory.setPdfMemoryUsageSetting(pdfMemoryUsageSetting);
		service.setPdfObjFactory(pdfObjFactory);

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		StepWithProfilingResult<ToBeSigned> getDataToSignData = runStepWithProfiling("getDataToSign", () -> service.getDataToSign(toBeSigned, params), pdfMemoryUsageSetting.getMode());
		stepPerfList.add(getDataToSignData);
		ToBeSigned dataToSign = getDataToSignData.result;

		StepWithProfilingResult<SignatureValue> tokenSignData = runStepWithProfiling("tokenSign", () -> {
			SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
			assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
			return signatureValue;
		}, pdfMemoryUsageSetting.getMode());
		stepPerfList.add(tokenSignData);
		SignatureValue signatureValue = tokenSignData.result;

		StepWithProfilingResult<DSSDocument> signDocumentData = runStepWithProfiling("signDocument", () -> service.signDocument(toBeSigned, params, signatureValue), pdfMemoryUsageSetting.getMode());
		stepPerfList.add(signDocumentData);
		DSSDocument signedDocument = signDocumentData.result;

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

		StepWithProfilingResult<DSSDocument> tLevelExtendDocumentData = runStepWithProfiling("T-Level extendDocument", () -> service.extendDocument(signedDocument, params), pdfMemoryUsageSetting.getMode());
		stepPerfList.add(tLevelExtendDocumentData);
		DSSDocument tLevelSignature = tLevelExtendDocumentData.result;

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

		StepWithProfilingResult<DSSDocument> ltLevelExtendDocumentData = runStepWithProfiling("LT-Level extendDocument", () -> service.extendDocument(tLevelSignature, params), pdfMemoryUsageSetting.getMode());
		stepPerfList.add(ltLevelExtendDocumentData);
		DSSDocument ltLevelSignature = ltLevelExtendDocumentData.result;

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		StepWithProfilingResult<DSSDocument> ltaLevelExtendDocumentData = runStepWithProfiling("LTA-Level extendDocument", () -> service.extendDocument(ltLevelSignature, params), pdfMemoryUsageSetting.getMode());
		stepPerfList.add(ltaLevelExtendDocumentData);
		DSSDocument ltaLevelSignature = ltaLevelExtendDocumentData.result;

		FileDocument ltaSignatureFileDocument = (FileDocument) ltaLevelSignature;
		File ltaSignatureFile = ltaSignatureFileDocument.getFile();
		return new CompleteSignProcessResult(ltaSignatureFile, stepPerfList);
	}

	private static <T> StepWithProfilingResult<T> runStepWithProfiling(String stepName, Supplier<T> step, PdfMemoryUsageSetting.Mode mode) {
		attemptFreeRuntimeMemory();
		Instant instantBefore = Instant.now();
		double memoryBefore = getRuntimeMemoryInMegabytes();

		T result = step.get();

		Instant instantAfter = Instant.now();
		double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
		double memoryDifference = memoryAfterGetDataToSign - memoryBefore;

		Duration timeDifference = Duration.between(instantBefore, instantAfter);
		LOG.info("[{}] Memory used for {} : {}Mb, Time: {}", mode, stepName, memoryDifference, timeDifference);
		return new StepWithProfilingResult<T>(result, stepName, memoryDifference, timeDifference);
	}

	private static void attemptFreeRuntimeMemory() {
		Runtime.getRuntime().gc();
		LOG.debug("Freeing up memory..");
		Runtime.getRuntime().gc(); // Empirically it is required to do more calls in order to properly clean-up
	}

	private static double getRuntimeMemoryInMegabytes() {
		// Get the Java runtime
		Runtime runtime = Runtime.getRuntime();
		// Calculate the used memory
		double memory = runtime.totalMemory() - runtime.freeMemory();
		return bytesToMegabytes(memory);
	}

	private static double bytesToMegabytes(double bytes) {
		return bytes / (1024L * 1024L);
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

	private static class CompleteSignProcessResult {

		private final File finalFile;
		private final List<StepWithProfilingResult<?>> stepWithProfilingResults;

		private CompleteSignProcessResult(File finalFile, List<StepWithProfilingResult<?>> stepWithProfilingResults) {
			this.finalFile = finalFile;
			this.stepWithProfilingResults = stepWithProfilingResults;
		}

	}

	private static class ValidateProcessResult {

		private final Reports reports;
		private final StepWithProfilingResult<?> stepWithProfilingResult;

		private ValidateProcessResult(Reports reports, StepWithProfilingResult<?> stepWithProfilingResult) {
			this.reports = reports;
			this.stepWithProfilingResult = stepWithProfilingResult;
		}

	}

	private static class StepWithProfilingResult<T> {

		private final T result;
		private final String stepName;
		private final double memoryDifference;
		private final Duration timeDifference;

		private StepWithProfilingResult(T result, String stepName, double memoryDifference, Duration timeDifference) {
			this.result = result;
			this.stepName = stepName;
			this.memoryDifference = memoryDifference;
			this.timeDifference = timeDifference;
		}

	}

}
